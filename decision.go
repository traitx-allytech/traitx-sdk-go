package traitx

import (
	"fmt"
	"strconv"
	"strings"
)

// HTTPOutcome is what the transport managed to obtain. It is data, never an
// error return, so the decision engine can stay a pure function.
type HTTPOutcome struct {
	StatusCode     int
	Body           map[string]interface{}
	TransportError string
	LatencyMS      int
	// BodyDecoded distinguishes "no body" from "body that was not JSON".
	BodyDecoded bool
}

// Decision is the result of Evaluate. See SPEC.md §7.
type Decision struct {
	// Action is the answer to act on.
	Action Action `json:"action"`
	// ObservedAction is what the chain said, even when not enforced.
	ObservedAction Action `json:"observed_action,omitempty"`
	// Enforced is false when the deciding policy was shadow-mode.
	Enforced bool   `json:"enforced"`
	Reason   Reason `json:"reason"`

	Score           float64         `json:"score"`
	RiskLevel       RiskLevel       `json:"risk_level"`
	Signals         []string        `json:"signals"`
	MatchedPolicies []MatchedPolicy `json:"matched_policies"`

	// Degraded is true when the decision did not come from a healthy evaluation.
	Degraded bool   `json:"degraded"`
	Error    string `json:"error,omitempty"`

	StatusCode int    `json:"status_code"`
	RequestID  string `json:"request_id"`
	LatencyMS  int    `json:"latency_ms"`

	// Raw is the full decoded response body.
	Raw map[string]interface{} `json:"-"`
}

// IsAllowed reports whether the action is allow.
//
// Do not branch on !IsDenied() — that lets challenges through unchallenged, which
// is the most common way this integration goes wrong.
func (d Decision) IsAllowed() bool { return d.Action == ActionAllow }

// RequiresChallenge reports whether a step-up is needed.
func (d Decision) RequiresChallenge() bool { return d.Action == ActionChallenge }

// IsDenied reports whether the request must be blocked.
func (d Decision) IsDenied() bool { return d.Action == ActionDeny }

// IsShadow reports whether a policy matched but was deployed pass-through.
func (d Decision) IsShadow() bool { return d.Reason == ReasonShadow }

// HasDeviceContext reports whether device enrichment reached the Risk API for
// this request_id. When false, every ip_enrichment.* and threats.* trigger was
// unreachable and those policies could not have matched. See SPEC.md §13.
func (d Decision) HasDeviceContext() bool {
	debug, ok := d.Raw["debug"].(map[string]interface{})
	if !ok {
		return true
	}
	for _, value := range debug {
		entry, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		if reason, ok := entry["reason"].(string); ok && reason == "no_enrichment_data" {
			return false
		}
	}
	return true
}

// String renders a one-line summary suitable for logs.
func (d Decision) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "TraitXDecision(action=%s reason=%s score=%g", d.Action, d.Reason, d.Score)
	if !d.Enforced && d.ObservedAction != "" {
		fmt.Fprintf(&b, " observed=%s", d.ObservedAction)
	}
	if d.Degraded {
		b.WriteString(" degraded")
	}
	b.WriteString(")")
	return b.String()
}

// ---------------------------------------------------------------------------
// Tolerant parsing — SPEC.md §5.1
// ---------------------------------------------------------------------------

var actionAliases = map[string]Action{
	"allow":     ActionAllow,
	"pass":      ActionAllow,
	"accept":    ActionAllow,
	"approve":   ActionAllow,
	"challenge": ActionChallenge,
	"stepup":    ActionChallenge,
	"step_up":   ActionChallenge,
	"review":    ActionChallenge,
	"deny":      ActionDeny,
	"block":     ActionDeny,
	"reject":    ActionDeny,
	"decline":   ActionDeny,
}

var clientErrorStatuses = map[int]bool{
	400: true, 401: true, 403: true, 404: true, 405: true, 409: true, 422: true,
}

// ParseAction parses an action from the wire. Case-insensitive, tolerates a
// leading "$". Anything unrecognised yields "" — treated as absent, never as
// allow, so a future action name can never silently open the gate.
func ParseAction(value interface{}) Action {
	s, ok := value.(string)
	if !ok {
		return ""
	}
	key := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "$")
	return actionAliases[key]
}

func firstOf(source map[string]interface{}, keys ...string) interface{} {
	if source == nil {
		return nil
	}
	for _, key := range keys {
		if value, ok := source[key]; ok && value != nil {
			return value
		}
	}
	return nil
}

func asMap(value interface{}) map[string]interface{} {
	m, _ := value.(map[string]interface{})
	return m
}

func asBool(value interface{}) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1" || v == "yes" || v == "TRUE" || v == "True"
	case float64:
		return v != 0
	case int:
		return v != 0
	}
	return false
}

func asFloat(value interface{}) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case string:
		if parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			return parsed, true
		}
	}
	return 0, false
}

func asString(value interface{}) string {
	s, _ := value.(string)
	return s
}

// ExtractChainAction reads the chain action from any shape the deployment may return.
func ExtractChainAction(body map[string]interface{}) Action {
	policy := asMap(body["policy"])
	decision := asMap(body["decision"])

	candidates := []interface{}{
		firstOf(policy, "action", "decision", "inline_action", "inlineAction"),
		firstOf(decision, "action", "decision"),
		body["decision"],
		body["action"],
	}
	for _, candidate := range candidates {
		if parsed := ParseAction(candidate); parsed != "" {
			return parsed
		}
	}
	return ""
}

// ExtractMatchedPolicies reads the matched-policy list from any shape the
// deployment may return.
func ExtractMatchedPolicies(body map[string]interface{}) []MatchedPolicy {
	policy := asMap(body["policy"])
	raw := firstOf(policy, "matched", "matched_policies", "matchedPolicies", "hits")
	if raw == nil {
		raw = firstOf(body, "matched_policies", "matchedPolicies", "matched")
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}

	matched := make([]MatchedPolicy, 0, len(list))
	for _, entry := range list {
		if id, ok := entry.(string); ok {
			// Some deployments return a bare list of policy ids.
			matched = append(matched, MatchedPolicy{ID: id, Name: id})
			continue
		}
		record := asMap(entry)
		if record == nil {
			continue
		}
		matched = append(matched, MatchedPolicy{
			ID:         asString(firstOf(record, "id", "policy_id", "policyId")),
			Name:       asString(firstOf(record, "name", "policy_name", "policyName")),
			Action:     ParseAction(firstOf(record, "action", "inline_action", "inlineAction")),
			EventGroup: asString(firstOf(record, "event_group", "eventGroup")),
			PassThrough: asBool(
				firstOf(record, "pass_through", "passThrough", "shadow", "pass_through_mode"),
			),
		})
	}
	return matched
}

// ExtractScore reads the risk score, defaulting to 0.
func ExtractScore(body map[string]interface{}) float64 {
	candidate := firstOf(body, "score", "risk_score", "riskScore")
	if candidate == nil {
		candidate = firstOf(asMap(body["data"]), "score", "risk_score", "riskScore")
	}
	if score, ok := asFloat(candidate); ok {
		return score
	}
	return 0
}

// ExtractSignals reads the fraud signal list.
func ExtractSignals(body map[string]interface{}) []string {
	candidate := firstOf(body, "signals", "risk_signals", "riskSignals")
	if candidate == nil {
		candidate = firstOf(asMap(body["data"]), "signals", "risk_signals", "riskSignals")
	}
	list, ok := candidate.([]interface{})
	if !ok {
		return nil
	}
	signals := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			signals = append(signals, s)
		}
	}
	return signals
}

// IsShadowed reports whether the chain's action is suppressed because the
// deciding policies are shadow-mode.
//
// True only when the relevant matched policies are all flagged pass-through. If
// none exposes a pass-through flag we assume the server is the authority and
// return false. See SPEC.md §6.1.
func IsShadowed(matched []MatchedPolicy, chainAction Action) bool {
	relevant := make([]MatchedPolicy, 0, len(matched))
	for _, p := range matched {
		if p.Action == chainAction {
			relevant = append(relevant, p)
		}
	}
	if len(relevant) == 0 {
		relevant = matched
	}
	if len(relevant) == 0 {
		return false
	}
	for _, p := range relevant {
		if !p.PassThrough {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Resolution — SPEC.md §6
// ---------------------------------------------------------------------------

// ResolveDecision turns an HTTP outcome into a Decision. Pure; unit-testable.
func ResolveDecision(outcome HTTPOutcome, cfg Config, requestID string) Decision {
	body := outcome.Body
	if body == nil {
		body = map[string]interface{}{}
	}

	score := ExtractScore(body)
	decision := Decision{
		Score:           score,
		RiskLevel:       RiskLevelFor(score),
		Signals:         ExtractSignals(body),
		MatchedPolicies: ExtractMatchedPolicies(body),
		StatusCode:      outcome.StatusCode,
		RequestID:       requestID,
		LatencyMS:       outcome.LatencyMS,
		Raw:             body,
	}

	// Step 1 — transport failure.
	if outcome.TransportError != "" || outcome.StatusCode >= 500 ||
		outcome.StatusCode == 429 || outcome.StatusCode == 408 || outcome.StatusCode == 0 {
		decision.Action = cfg.FailureMode
		decision.Reason = ReasonDegraded
		decision.Degraded = true
		decision.Enforced = false
		decision.Error = outcome.TransportError
		if decision.Error == "" {
			decision.Error = fmt.Sprintf("risk api returned HTTP %d", outcome.StatusCode)
		}
		return applyHook(decision, cfg)
	}

	// Step 2 — client error. A rotated key is an engineering fault, not a verdict.
	if clientErrorStatuses[outcome.StatusCode] || outcome.StatusCode >= 400 {
		decision.Action = cfg.ClientErrorMode
		decision.Reason = ReasonClientError
		decision.Degraded = true
		decision.Enforced = false
		decision.Error = describeAPIError(outcome.StatusCode, body)
		return applyHook(decision, cfg)
	}

	// A 2xx we could not decode is a transport failure, not an allow.
	if !outcome.BodyDecoded {
		decision.Action = cfg.FailureMode
		decision.Reason = ReasonDegraded
		decision.Degraded = true
		decision.Enforced = false
		decision.Error = fmt.Sprintf(
			"risk api returned HTTP %d with a body that is not JSON", outcome.StatusCode)
		return applyHook(decision, cfg)
	}

	// Step 3 — the policy chain decided.
	if chainAction := ExtractChainAction(body); chainAction != "" {
		shadowed := IsShadowed(decision.MatchedPolicies, chainAction)
		decision.ObservedAction = chainAction
		decision.Enforced = !shadowed
		if shadowed && !cfg.EnforceShadowDecisions {
			decision.Action = ActionAllow
			decision.Reason = ReasonShadow
		} else {
			decision.Action = chainAction
			decision.Reason = ReasonPolicyMatch
		}
		return applyHook(decision, cfg)
	}

	// Step 4 — derive from score, then let configured signals escalate.
	action := ActionAllow
	reason := ReasonNoMatch

	switch {
	case score >= cfg.Thresholds.Deny:
		action, reason = ActionDeny, ReasonScoreThreshold
	case score >= cfg.Thresholds.Challenge:
		action, reason = ActionChallenge, ReasonScoreThreshold
	}

	present := make(map[string]bool, len(decision.Signals))
	for _, s := range decision.Signals {
		present[s] = true
	}
	signalAction := ActionAllow
	if anyPresent(present, cfg.DenyOnSignals) {
		signalAction = ActionDeny
	} else if anyPresent(present, cfg.ChallengeOnSignals) {
		signalAction = ActionChallenge
	}
	if Severity(signalAction) > Severity(action) {
		action, reason = signalAction, ReasonSignalOverride
	}

	decision.Action = action
	decision.Reason = reason
	decision.Enforced = true
	return applyHook(decision, cfg)
}

func applyHook(d Decision, cfg Config) Decision {
	if cfg.OnDecision == nil {
		return d
	}
	if replacement := cfg.OnDecision(d); replacement != nil {
		return *replacement
	}
	return d
}

func anyPresent(present map[string]bool, candidates []string) bool {
	for _, candidate := range candidates {
		if present[candidate] {
			return true
		}
	}
	return false
}

func describeAPIError(status int, body map[string]interface{}) string {
	parts := make([]string, 0, 2)
	if s := asString(body["error"]); s != "" {
		parts = append(parts, s)
	}
	if s := asString(body["message"]); s != "" {
		parts = append(parts, s)
	}
	base := fmt.Sprintf("risk api rejected the request (HTTP %d)", status)
	if len(parts) == 0 {
		return base
	}
	return base + ": " + strings.Join(parts, ": ")
}
