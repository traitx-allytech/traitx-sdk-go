// Package traitx is the TraitX decision SDK: it evaluates a risk event against
// your policy chain and returns one of three answers — allow, challenge or deny.
//
// Wire contract and decision algorithm: sdk/SPEC.md.
//
//	client, err := traitx.New(traitx.Config{
//	    BaseURL:       os.Getenv("TRAITX_BASE_URL"),
//	    APIKey:        os.Getenv("TRAITX_PRIVATE_KEY"),
//	    ApplicationID: os.Getenv("TRAITX_APPLICATION_ID"),
//	})
//
//	decision := client.EvaluateLogin(ctx, traitx.Event{
//	    RequestID: r.Header.Get("X-TraitX-Request-Id"),
//	    User:      &traitx.User{ID: user.ID, Email: user.Email},
//	    Context:   traitx.ContextFromRequest(r),
//	})
//
//	switch decision.Action {
//	case traitx.ActionDeny:
//	    http.Error(w, "access denied", http.StatusForbidden)
//	case traitx.ActionChallenge:
//	    sendOTP(user)
//	default:
//	    issueToken(w, user)
//	}
package traitx

import "time"

// Action is one of the three answers the SDK can give. See SPEC.md §1.
type Action string

const (
	ActionAllow     Action = "allow"
	ActionChallenge Action = "challenge"
	ActionDeny      Action = "deny"
)

// Reason records how a decision was reached. See SPEC.md §6.
type Reason string

const (
	// ReasonPolicyMatch means a policy in the chain matched and is enforced.
	ReasonPolicyMatch Reason = "policy_match"
	// ReasonShadow means a policy matched but is deployed pass-through, so
	// nothing is enforced.
	ReasonShadow Reason = "shadow"
	// ReasonScoreThreshold means no policy action; the score crossed a threshold.
	ReasonScoreThreshold Reason = "score_threshold"
	// ReasonSignalOverride means no policy action; a configured signal escalated.
	ReasonSignalOverride Reason = "signal_override"
	// ReasonNoMatch means nothing matched and the score is below every threshold.
	ReasonNoMatch Reason = "no_match"
	// ReasonDegraded means the Risk API could not be reached; FailureMode applied.
	ReasonDegraded Reason = "degraded"
	// ReasonClientError means the Risk API rejected the request; ClientErrorMode applied.
	ReasonClientError Reason = "client_error"
)

// RiskLevel is an informational banding derived from the score. See SPEC.md §6.2.
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// EventType is a policy event group, mirroring PolicyEventGroup in
// models/policy.go.
//
// $before_all and $after_all are intentionally absent: they are chain hooks that
// run on every event, not event types you can send. See SPEC.md §4.
type EventType string

const (
	EventLogin                EventType = "$login"
	EventRegistration         EventType = "$registration"
	EventLogout               EventType = "$logout"
	EventTransaction          EventType = "$transaction"
	EventChallenge            EventType = "$challenge"
	EventProfile              EventType = "$profile"
	EventProfileUpdate        EventType = "$profile_update"
	EventProfileReset         EventType = "$profile_reset"
	EventPasswordResetRequest EventType = "$password_reset_request"
	EventCustom               EventType = "$custom"
	EventGeneric              EventType = "$generic"
)

// EventStatus is the outcome of the business event being reported.
type EventStatus string

const (
	StatusSucceeded EventStatus = "$succeeded"
	StatusFailed    EventStatus = "$failed"
)

// Address is the user's postal address, if you hold one.
type Address struct {
	Line1       string
	Line2       string
	City        string
	RegionCode  string
	PostalCode  string
	CountryCode string
	Latitude    float64
	Longitude   float64
}

// User describes the account the event belongs to.
type User struct {
	ID           string
	Email        string
	Name         string
	FirstName    string
	LastName     string
	Username     string
	Phone        string
	NationalID   string
	CreatedAt    *time.Time
	RegisteredAt *time.Time
	UpdatedAt    *time.Time
	Address      *Address
}

// Session identifies the user's session.
type Session struct {
	ID        string
	CreatedAt *time.Time
}

// RequestContext describes the *end user's* request, not your server's.
//
// Headers is an ordered list of pairs because headers can repeat and the policy
// engine matches on ordered pairs. See SPEC.md §3.1.
type RequestContext struct {
	IP      string
	Headers [][2]string
}

// Event is one input to Evaluate.
type Event struct {
	// RequestID is the requestId produced by the browser collector's get().
	// Without it the event carries no device context.
	RequestID string
	Type      EventType
	Status    EventStatus
	CreatedAt *time.Time
	Session   *Session
	Context   *RequestContext

	User *User

	// Attributes are business fields merged into the event root, e.g. "amount",
	// "merchant.mcc". A dotted key is a literal key name, never a nested object.
	// See SPEC.md §3.2.
	Attributes map[string]interface{}
}

// MatchedPolicy is a policy the chain reported as matched.
type MatchedPolicy struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Action     Action `json:"action,omitempty"`
	EventGroup string `json:"event_group,omitempty"`
	// PassThrough is true when the policy is deployed in shadow mode and must
	// not enforce.
	PassThrough bool `json:"pass_through"`
}

// RiskLevelFor maps a score to a risk level. See SPEC.md §6.2.
func RiskLevelFor(score float64) RiskLevel {
	switch {
	case score >= 80:
		return RiskLevelCritical
	case score >= 60:
		return RiskLevelHigh
	case score >= 30:
		return RiskLevelMedium
	default:
		return RiskLevelLow
	}
}

// Severity is the ordering used when escalating between actions. See SPEC.md §6.
func Severity(a Action) int {
	switch a {
	case ActionDeny:
		return 2
	case ActionChallenge:
		return 1
	default:
		return 0
	}
}
