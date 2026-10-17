package hub

import (
	"context"
	"log/slog"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// orgEval evaluates the org rule for (email, ns, device) from the live sources.
// It makes no Kubernetes calls.
func (h *Hub) orgEval(email, ns, device string) (bool, string) {
	doc, docOK := h.deps.Org.Doc(ns)
	entry, entryOK := h.deps.Flags.Flags(ns, device)
	return orgDecision(doc, docOK, entry, entryOK, email)
}

func orgDenial(reason string) *denial {
	if reason == orgReasonUnavailable {
		return deny(api.ReasonForbidden, orgMsgUnavailable)
	}
	return deny(api.ReasonForbidden, orgMsgScope)
}

// canOpen answers whether email may open a session to (ns, device): a valid
// lowercase email, the per-teamspace SubjectAccessReview, then the org gate. A
// nil denial means allowed; an error is an unavailable authorizer (the caller
// fails closed as before).
func (h *Hub) canOpen(ctx context.Context, email, ns, device string) (*denial, error) {
	if !ValidEmail(email) {
		return deny(api.ReasonForbidden, "no access to this teamspace"), nil
	}
	allowed, err := h.deps.Authz.CanExec(ctx, email, ns)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return deny(api.ReasonForbidden, "no access to this teamspace"), nil
	}
	mode := h.cfg.OrgGateMode
	if mode == OrgGateOff {
		return nil, nil
	}
	ok, reason := h.orgEval(email, ns, device)
	switch {
	case ok:
		h.met.orgGate.WithLabelValues(mode, "allow", reason).Inc()
		return nil, nil
	case mode == OrgGateAudit:
		h.met.orgGate.WithLabelValues(mode, "would_deny", reason).Inc()
		h.log.Warn("org gate would deny", "reason", reason, "ns", ns, "device", device, "subject", email)
		return nil, nil
	}
	h.met.orgGate.WithLabelValues(mode, "deny", reason).Inc()
	return orgDenial(reason), nil
}

// orgNotify is the change callback of the org and flags sources.
func (h *Hub) orgNotify(ns, device string) {
	h.pendMu.Lock()
	h.orgPending[devKey{ns, device}] = struct{}{}
	h.pendMu.Unlock()
	select {
	case h.orgWake <- struct{}{}:
	default:
	}
}

func (h *Hub) orgEnforcer() {
	defer h.wg.Done()
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-h.orgWake:
		}
		h.pendMu.Lock()
		keys := make([]devKey, 0, len(h.orgPending))
		for k := range h.orgPending {
			keys = append(keys, k)
		}
		clear(h.orgPending)
		h.pendMu.Unlock()
		for _, k := range keys {
			h.orgEnforce(k)
		}
	}
}

// orgEnforce re-runs only the org gate (no SubjectAccessReview) for the client
// sessions of a device, or of a whole teamspace when k.device is empty. Denied
// sessions end like a denied renewal; the users of a perConn (web gateway)
// session are re-checked by the user rechecker.
func (h *Hub) orgEnforce(k devKey) {
	if h.cfg.OrgGateMode != OrgGateEnforce {
		return
	}
	var sessions []*session
	h.mu.Lock()
	for dk, m := range h.clients {
		if dk.ns != k.ns || (k.device != "" && dk.device != k.device) {
			continue
		}
		for _, s := range m {
			sessions = append(sessions, s)
		}
	}
	h.mu.Unlock()
	for _, s := range sessions {
		if s.perConn {
			select {
			case h.recheck <- struct{}{}:
			default:
			}
			continue
		}
		if ok, reason := h.orgEval(s.subject, s.ns, s.device); !ok && h.endSession(s, orgReasonScope) {
			h.met.revocations.WithLabelValues(orgReasonScope).Inc()
			h.met.orgGate.WithLabelValues(OrgGateEnforce, "deny", reason).Inc()
			h.logRevoke(s.key(), api.ReasonForbidden, orgDenial(reason).msg, s.id, slog.String("org_reason", reason))
		}
	}
}
