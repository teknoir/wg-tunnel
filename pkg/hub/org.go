package hub

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/teknoir/wg-tunnel/pkg/api"
)

// The org gate narrows the per-teamspace SubjectAccessReview: a user who is a
// member of the teamspace's organisation tree may open only the devices that
// are unplaced or sit on a path containing one of the user's units. The rule
// and its vectors: plans/nextgen/org-gate-rule.md (testdata/org-gate-vectors.json).

// Org gate modes (ORG_GATE_MODE).
const (
	OrgGateEnforce = "enforce"
	OrgGateAudit   = "audit"
	OrgGateOff     = "off"
)

// ParseOrgGateMode validates an ORG_GATE_MODE value; empty means enforce.
func ParseOrgGateMode(s string) (string, error) {
	switch s {
	case "", OrgGateEnforce:
		return OrgGateEnforce, nil
	case OrgGateAudit, OrgGateOff:
		return s, nil
	}
	return "", fmt.Errorf("ORG_GATE_MODE must be enforce, audit or off, got %q", s)
}

// Org gate reasons (log and metric labels; the wire reason stays "forbidden").
const (
	orgReasonScope       = "org_scope"
	orgReasonUnavailable = "org_scope_unavailable"
)

const (
	orgMsgScope       = "this device is outside your organisation units"
	orgMsgUnavailable = "organisation data is not available yet; try again shortly"
)

var unitIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)

// OrgSource serves the per-teamspace org documents written by the flags watcher.
type OrgSource interface {
	// Doc returns the org document of a teamspace; ok is false when there is
	// none (the hub then fails closed for organisation members).
	Doc(ns string) (doc api.OrgDoc, ok bool)
	// Subscribe registers fn, called with (ns, "") after the document of ns
	// was added, changed or removed. fn must not block.
	Subscribe(fn func(ns, device string))
	HasSynced() bool
}

// UserProjection is the part of a User CR the org gate needs. Nothing else of
// the User (its status holds an initial password) is ever retained.
type UserProjection struct {
	Name        string
	Email       string // raw spec.email
	Role        string // spec.claims_v0.role
	ClaimSets   []ClaimSetRef
	Annotations map[string]string // only teknoir.org/org-tree-member-* and -units-*
}

// ClaimSetRef is one entry of spec.claim_set.
type ClaimSetRef struct{ Name, Namespace string }

// orgUnits parses the units annotation: valid unit ids only, [] when missing,
// unparsable or not an array of strings.
func orgUnits(raw string) []string {
	units := []string{}
	var arr []any
	if raw == "" || json.Unmarshal([]byte(raw), &arr) != nil {
		return units
	}
	for _, v := range arr {
		if s, ok := v.(string); ok && unitIDRe.MatchString(s) && !slices.Contains(units, s) {
			units = append(units, s)
		}
	}
	sort.Strings(units)
	return units
}

func orgMember(u UserProjection, ns string) bool {
	v := u.Annotations[api.AnnotationOrgMemberPref+ns]
	return v != "" && v != "false"
}

func orgExempt(u UserProjection, ns string) bool {
	if u.Role == "superadmin" {
		return true
	}
	for _, c := range u.ClaimSets {
		if c.Name == "owner" && c.Namespace == ns {
			return true
		}
	}
	return false
}

// buildOrgDoc computes the org document of a teamspace from the Users. Users
// whose email is invalid are skipped (logged by CR name only); an email that
// several User CRs claim is a member without units and not exempt (fail closed).
func buildOrgDoc(users []UserProjection, ns string, log *slog.Logger) api.OrgDoc {
	doc := api.OrgDoc{V: api.OrgDocVersion, Namespace: ns, Members: map[string]api.OrgMember{}, Exempt: []string{}}
	byEmail := map[string][]UserProjection{}
	for _, u := range users {
		email := strings.ToLower(strings.TrimSpace(u.Email))
		if !ValidEmail(email) {
			if log != nil {
				log.Warn("org: skipping User with an invalid email", "user", u.Name)
			}
			continue
		}
		byEmail[email] = append(byEmail[email], u)
	}
	for email, us := range byEmail {
		if len(us) > 1 {
			if log != nil {
				log.Warn("org: several Users share an email; failing closed", "count", len(us), "user", us[0].Name)
			}
			doc.Members[email] = api.OrgMember{Units: []string{}}
			continue
		}
		u := us[0]
		if orgExempt(u, ns) {
			doc.Exempt = append(doc.Exempt, email)
		}
		if orgMember(u, ns) {
			doc.Members[email] = api.OrgMember{Units: orgUnits(u.Annotations[api.AnnotationOrgUnitsPref+ns])}
		}
	}
	sort.Strings(doc.Exempt)
	return doc
}

// marshalOrgDoc renders the canonical JSON (map keys are sorted by encoding/json).
func marshalOrgDoc(d api.OrgDoc) (string, error) {
	if d.Members == nil {
		d.Members = map[string]api.OrgMember{}
	}
	if d.Exempt == nil {
		d.Exempt = []string{}
	}
	for k, m := range d.Members {
		if m.Units == nil {
			d.Members[k] = api.OrgMember{Units: []string{}}
		}
	}
	b, err := json.Marshal(d)
	return string(b), err
}

// ParseOrgConfigMap validates an org ConfigMap strictly. The returned string
// is the problem ("" when valid); a problem means the document is missing.
func ParseOrgConfigMap(cm *corev1.ConfigMap) (api.OrgDoc, string) {
	var d api.OrgDoc
	ns := cm.Labels[api.PolicyTeamspaceLabel]
	if cm.Labels[api.OrgLabel] != "true" {
		return d, "missing org label"
	}
	raw, ok := cm.Data[api.OrgDataKey]
	if !ok {
		return d, "missing " + api.OrgDataKey
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil || dec.More() {
		return api.OrgDoc{}, "malformed org JSON"
	}
	if d.Members == nil || d.Exempt == nil {
		return api.OrgDoc{}, "malformed org JSON"
	}
	for e := range d.Members {
		if !ValidEmail(e) {
			return api.OrgDoc{}, "invalid member email"
		}
	}
	for _, e := range d.Exempt {
		if !ValidEmail(e) {
			return api.OrgDoc{}, "invalid exempt email"
		}
	}
	if d.V != api.OrgDocVersion {
		return api.OrgDoc{}, "unsupported version"
	}
	if !validLabel(ns) || d.Namespace != ns || cm.Name != api.OrgConfigMapName(ns) {
		return api.OrgDoc{}, "namespace, label and name disagree"
	}
	return d, ""
}

// orgDecision is the pure org rule (see the package comment). docOK is false
// when the teamspace has no usable org document; entryOK when the device's
// flags entry exists. The reason of an allow is informational.
func orgDecision(doc api.OrgDoc, docOK bool, entry api.FlagsEntry, entryOK bool, email string) (bool, string) {
	if !docOK {
		return false, orgReasonUnavailable
	}
	if slices.Contains(doc.Exempt, email) {
		return true, "exempt"
	}
	member, isMember := doc.Members[email]
	if !isMember {
		return true, "not_member"
	}
	if !entryOK || !entry.OrgKnown {
		return false, orgReasonUnavailable
	}
	var path []string
	for _, p := range strings.Split(entry.OrgPath, "/") {
		if p != "" {
			path = append(path, p)
		}
	}
	if len(path) == 0 && entry.OrgNodeID != "" {
		path = []string{entry.OrgNodeID}
	}
	if len(path) == 0 {
		return true, "unplaced"
	}
	for _, u := range member.Units {
		if unitIDRe.MatchString(u) && slices.Contains(path, u) {
			return true, "unit_match"
		}
	}
	return false, orgReasonScope
}
