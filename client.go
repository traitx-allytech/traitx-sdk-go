package traitx

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// Client evaluates risk events. Build one per process and reuse it: the circuit
// breaker state lives on the instance, so a client per request would never open.
//
// Client is safe for concurrent use.
type Client struct {
	cfg       Config
	transport *transport
	breaker   *CircuitBreaker

	// Management exposes the portal policy and list APIs. See management.go.
	Management *Management
}

// New validates the configuration, applies defaults and returns a Client.
func New(cfg Config) (*Client, error) {
	if err := cfg.applyDefaults(); err != nil {
		return nil, err
	}
	breaker := NewCircuitBreaker(cfg.Breaker, cfg.Clock)
	tr := &transport{cfg: cfg, breaker: breaker}
	client := &Client{cfg: cfg, transport: tr, breaker: breaker}
	client.Management = &Management{cfg: cfg, transport: tr}
	return client, nil
}

// MustNew is New that panics on a bad configuration. Use it at process start,
// where a misconfiguration should stop the deployment.
func MustNew(cfg Config) *Client {
	client, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return client
}

// Config returns a copy of the resolved configuration.
func (c *Client) Config() Config { return c.cfg }

// BreakerState reports the circuit breaker state, for your own health endpoint.
func (c *Client) BreakerState() BreakerState { return c.breaker.State() }

// Evaluate sends an event and returns the decision to act on.
//
// It returns an error only for an event the SDK refuses to send — a bug in the
// calling code, which should fail in tests. Network and API failures are not
// errors: they degrade to cfg.FailureMode / cfg.ClientErrorMode with
// Degraded set, so a TraitX outage cannot take your login or checkout path down.
func (c *Client) Evaluate(ctx context.Context, event Event) (Decision, error) {
	payload, err := SerializeEvent(event, c.cfg.Clock())
	if err != nil {
		return Decision{}, err
	}

	outcome := c.transport.send(ctx, requestSpec{
		method: "POST",
		path:   "/api/v1/risk",
		body:   payload,
	})

	decision := ResolveDecision(outcome, c.cfg, event.RequestID)

	if c.cfg.Debug {
		c.cfg.Logger.Printf("[traitx] %s", decision)
	}

	return decision, nil
}

// MustEvaluate is Evaluate for call sites that cannot handle a validation error.
// A validation failure degrades to cfg.FailureMode with the error attached,
// rather than panicking in a request path.
func (c *Client) MustEvaluate(ctx context.Context, event Event) Decision {
	decision, err := c.Evaluate(ctx, event)
	if err != nil {
		return Decision{
			Action:     c.cfg.FailureMode,
			Reason:     ReasonDegraded,
			Degraded:   true,
			Error:      err.Error(),
			RequestID:  event.RequestID,
			RiskLevel:  RiskLevelLow,
			Raw:        map[string]interface{}{},
			Enforced:   false,
			StatusCode: 0,
		}
	}
	return decision
}

func (c *Client) evaluateAs(ctx context.Context, eventType EventType, event Event) (Decision, error) {
	event.Type = eventType
	return c.Evaluate(ctx, event)
}

// EvaluateLogin is the $login shorthand.
func (c *Client) EvaluateLogin(ctx context.Context, event Event) (Decision, error) {
	return c.evaluateAs(ctx, EventLogin, event)
}

// EvaluateRegistration is the $registration shorthand.
func (c *Client) EvaluateRegistration(ctx context.Context, event Event) (Decision, error) {
	return c.evaluateAs(ctx, EventRegistration, event)
}

// EvaluatePasswordReset is the $password_reset_request shorthand.
func (c *Client) EvaluatePasswordReset(ctx context.Context, event Event) (Decision, error) {
	return c.evaluateAs(ctx, EventPasswordResetRequest, event)
}

// EvaluateProfileUpdate is the $profile_update shorthand.
func (c *Client) EvaluateProfileUpdate(ctx context.Context, event Event) (Decision, error) {
	return c.evaluateAs(ctx, EventProfileUpdate, event)
}

// Transaction carries the transaction fields for EvaluateTransaction. They are
// sent as root-level attributes, which is where transaction policy triggers look
// for them.
type Transaction struct {
	Amount   float64
	Currency string
	PayeeID  string
}

// EvaluateTransaction is the $transaction shorthand.
func (c *Client) EvaluateTransaction(
	ctx context.Context, event Event, tx Transaction,
) (Decision, error) {
	attributes := make(map[string]interface{}, len(event.Attributes)+3)
	if tx.Amount != 0 {
		attributes["amount"] = tx.Amount
	}
	if tx.Currency != "" {
		attributes["currency"] = tx.Currency
	}
	if tx.PayeeID != "" {
		attributes["payee_id"] = tx.PayeeID
	}
	for key, value := range event.Attributes {
		attributes[key] = value
	}
	event.Attributes = attributes
	return c.evaluateAs(ctx, EventTransaction, event)
}

// ReportChallengeOutcome reports the outcome of a step-up you issued, so
// $challenge policies can react to repeated failures.
func (c *Client) ReportChallengeOutcome(
	ctx context.Context, event Event, passed bool,
) (Decision, error) {
	if passed {
		event.Status = StatusSucceeded
	} else {
		event.Status = StatusFailed
	}
	return c.evaluateAs(ctx, EventChallenge, event)
}

// Fingerprint returns the full device fingerprint for a collector request_id.
// Useful for case review and for enriching your own fraud store; not needed for
// a decision.
func (c *Client) Fingerprint(ctx context.Context, requestID string) (map[string]interface{}, error) {
	if strings.TrimSpace(requestID) == "" {
		return nil, fmt.Errorf("traitx: requestID is required")
	}
	outcome := c.transport.send(ctx, requestSpec{
		method: "GET",
		path:   "/api/v1/fingerprint/" + url.PathEscape(requestID),
	})
	if outcome.TransportError != "" {
		return nil, fmt.Errorf("traitx: %s", outcome.TransportError)
	}
	if outcome.StatusCode >= 400 {
		return nil, &APIError{
			StatusCode: outcome.StatusCode,
			Body:       outcome.Body,
			Message:    fmt.Sprintf("fingerprint lookup failed with HTTP %d", outcome.StatusCode),
		}
	}
	if outcome.Body == nil {
		return map[string]interface{}{}, nil
	}
	return outcome.Body, nil
}

// Health probes GET /health.
func (c *Client) Health(ctx context.Context) bool {
	outcome := c.transport.send(ctx, requestSpec{method: "GET", path: "/health"})
	return outcome.TransportError == "" &&
		outcome.StatusCode >= 200 && outcome.StatusCode < 300
}

// APIError is returned by the calls that fail loudly rather than degrading.
type APIError struct {
	StatusCode int
	Body       map[string]interface{}
	Message    string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return "traitx: " + e.Message
	}
	return fmt.Sprintf("traitx: API error (HTTP %d)", e.StatusCode)
}

// DoctorFinding is one check from Doctor.
type DoctorFinding struct {
	Check  string
	OK     bool
	Detail string
}

// DoctorReport is the result of Doctor.
type DoctorReport struct {
	OK       bool
	Findings []DoctorFinding
}

// Doctor runs a connectivity and configuration self-check, returning findings
// rather than an error so it can run at boot or from a CLI. See SPEC.md §13.
//
// Pass a real collector requestID to also verify that the key is accepted, that
// IP enrichment is attached and that the chain returns an action.
func (c *Client) Doctor(ctx context.Context, probeRequestID string) DoctorReport {
	report := DoctorReport{}
	add := func(check string, ok bool, detail string) {
		report.Findings = append(report.Findings, DoctorFinding{check, ok, detail})
	}

	isPrivate := strings.HasPrefix(c.cfg.APIKey, "trx_pvk_")
	detail := fmt.Sprintf("private key %s", RedactKey(c.cfg.APIKey))
	if !isPrivate {
		detail = fmt.Sprintf("key %s is not a trx_pvk_ private key", RedactKey(c.cfg.APIKey))
	}
	add("api key class", isPrivate, detail)

	healthy := c.Health(ctx)
	state := "did not respond"
	if healthy {
		state = "responded"
	}
	add("deployment reachable", healthy, c.cfg.BaseURL+"/health "+state)

	if c.cfg.ApplicationID != "" {
		add("application scoping", true, "X-Application-ID "+c.cfg.ApplicationID)
	} else {
		add("application scoping", false,
			"no ApplicationID set — management calls will fall back to the tenant's oldest "+
				"active application, which is rarely the one holding your policies")
	}

	if probeRequestID != "" {
		decision, err := c.EvaluateLogin(ctx, Event{RequestID: probeRequestID})
		if err != nil {
			add("risk api accepts the key", false, err.Error())
		} else {
			keyOK := decision.Reason != ReasonClientError
			keyDetail := decision.Error
			if keyDetail == "" {
				keyDetail = fmt.Sprintf("HTTP %d, reason %s", decision.StatusCode, decision.Reason)
			}
			add("risk api accepts the key", keyOK, keyDetail)

			if decision.HasDeviceContext() {
				add("device enrichment present", true,
					"IP enrichment attached; ip_enrichment.* policies can match")
			} else {
				add("device enrichment present", false,
					"no enrichment for this request_id — ip_enrichment.* triggers cannot match")
			}

			if decision.ObservedAction != "" {
				add("policy chain returns an action", true,
					fmt.Sprintf("chain action %s, %d matched",
						decision.ObservedAction, len(decision.MatchedPolicies)))
			} else {
				add("policy chain returns an action", false,
					"no chain action in the response; decisions will fall back to score thresholds")
			}
		}
	}

	report.OK = true
	for _, finding := range report.Findings {
		if !finding.OK {
			report.OK = false
		}
	}
	return report
}
