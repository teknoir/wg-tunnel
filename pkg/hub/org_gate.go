package hub

import (
	"context"
	"log/slog"
	"strings"

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
// lowercase email, the per-teamspace SubjectAccessReview, the TeknoirBot cover
// rule (in every org-gate mode), then the org gate. A nil denial means allowed;
// an error is an unavailable authorizer (the caller fails closed as before).
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
	if den, err := h.botCover(ctx, email, ns, device); den != nil || err != nil {
		return den, err
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

// botCover enforces the TeknoirBot cover rule: a bot's agent acts with its
// creator's platform rights, so opening the bot borrows them. Only the creator
// may open it under access "creator" (or an unknown value); under "read" and
// "none" the creator or a teamspace admin may. A tb- device whose flags entry
// has no bot fields (an older watcher) fails closed. It makes at most one
// SubjectAccessReview, and never for the creator.
func (h *Hub) botCover(ctx context.Context, email, ns, device string) (*denial, error) {
	entry, ok := h.deps.Flags.Flags(ns, device)
	// A tb- device is a bot by its name: its entry must carry bot fields that
	// name exactly this device, or it fails closed (an older watcher, or a
	// Device whose label was removed or does not match its name).
	if strings.HasPrefix(device, api.BotDevicePrefix) &&
		(!ok || !entry.BotKnown || entry.Bot == "" || api.BotDevicePrefix+entry.Bot != device) {
		h.botCoverDenied(ns, device, email, "unknown")
		return deny(api.ReasonForbidden, "this TeknoirBot's access is not known yet"), nil
	}
	if !ok || entry.Bot == "" {
		return nil, nil // not a bot
	}
	creator := normBotCreator(entry.BotCreator)
	switch entry.BotAccess {
	case api.BotAccessRead, api.BotAccessNone:
		if creator != "" && email == creator {
			h.met.botCover.WithLabelValues("creator").Inc()
			return nil, nil
		}
		admin, err := h.deps.Authz.CanAdmin(ctx, email, ns)
		if err != nil {
			return nil, err
		}
		if admin {
			h.met.botCover.WithLabelValues("admin").Inc()
			return nil, nil
		}
		h.botCoverDenied(ns, device, email, "deny")
		return deny(api.ReasonForbidden, "only this TeknoirBot's creator and teamspace admins can open it"), nil
	default: // creator, "" and anything unknown: only the creator
		if creator != "" && email == creator {
			h.met.botCover.WithLabelValues("creator").Inc()
			return nil, nil
		}
		h.botCoverDenied(ns, device, email, "deny")
		return deny(api.ReasonForbidden, "this TeknoirBot acts as its creator; only its creator can open it"), nil
	}
}

// normBotCreator normalises the creator annotation for comparison with a session
// subject: surrounding space trimmed and ASCII lower-cased. Anything that is not
// then a valid ASCII email (ValidEmail) gives "", which matches no subject; this
// keeps Unicode case folding (e.g. the Kelvin sign) from matching another user.
func normBotCreator(raw string) string {
	s := strings.TrimSpace(raw)
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return ""
		}
	}
	s = strings.ToLower(s)
	if !ValidEmail(s) {
		return ""
	}
	return s
}

// botCoverDenied counts and logs a refused bot cover decision.
func (h *Hub) botCoverDenied(ns, device, email, decision string) {
	h.met.botCover.WithLabelValues(decision).Inc()
	h.log.Info("bot cover denied", "ns", ns, "device", device, "subject", email, "bot_cover", decision)
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
		if ok, reason := h.orgEval(s.subject, s.ns, s.device); !ok && h.endSession(s, reason) {
			h.met.revocations.WithLabelValues(reason).Inc()
			h.met.orgGate.WithLabelValues(OrgGateEnforce, "deny", reason).Inc()
			h.logRevoke(s.key(), api.ReasonForbidden, orgDenial(reason).msg, s.id, slog.String("org_reason", reason))
		}
	}
}
