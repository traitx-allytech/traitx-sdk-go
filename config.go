package traitx

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// Version is the SDK version, sent in the User-Agent.
const Version = "1.0.0"

// Thresholds are the score bands used only when the policy chain returned no
// action. See SPEC.md §6 step 4.
type Thresholds struct {
	Challenge float64
	Deny      float64
}

// BreakerConfig tunes the circuit breaker. See SPEC.md §10.
type BreakerConfig struct {
	FailureThreshold int
	ResetAfter       time.Duration
}

// Config configures a Client. Only BaseURL and APIKey are required; everything
// else has a sensible default applied by New.
type Config struct {
	// BaseURL is the tenant deployment, e.g. "https://traitx.allytech.sa".
	BaseURL string
	// APIKey is the private key, "trx_pvk_…". Server-side only.
	APIKey string
	// ApplicationID is sent as X-Application-ID. Required for management calls.
	ApplicationID string

	// Timeout is the per-attempt timeout. Default 2500ms.
	Timeout time.Duration
	// MaxRetries is the number of extra attempts after the first.
	// Zero means "use the default" (2); use -1 to disable retries entirely.
	MaxRetries int
	// RetryBackoff is the base for exponential backoff with full jitter. Default 100ms.
	RetryBackoff time.Duration

	// FailureMode is returned when TraitX is unreachable. Default ActionAllow.
	FailureMode Action
	// ClientErrorMode is returned when TraitX rejects the request. Default ActionAllow.
	ClientErrorMode Action

	Thresholds Thresholds
	// DenyOnSignals escalate to deny when the chain gave no action.
	DenyOnSignals []string
	// ChallengeOnSignals escalate to challenge when the chain gave no action.
	ChallengeOnSignals []string

	// EnforceShadowDecisions enforces actions from pass-through policies.
	EnforceShadowDecisions bool

	Breaker BreakerConfig

	UserAgent string
	// Debug logs requests and responses with the API key redacted.
	Debug  bool
	Logger *log.Logger

	// OnDecision post-processes every decision. Return a replacement or nil.
	OnDecision func(Decision) *Decision

	// HTTPClient is used for all calls. Default is a client with sane transport
	// settings; supply your own to control connection pooling or add tracing.
	HTTPClient *http.Client

	// Clock is used for the breaker and for timestamps. Default time.Now.
	Clock func() time.Time
}

func (c *Config) applyDefaults() error {
	c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if c.BaseURL == "" {
		return fmt.Errorf("traitx: BaseURL is required")
	}
	if !strings.HasPrefix(c.BaseURL, "http://") && !strings.HasPrefix(c.BaseURL, "https://") {
		return fmt.Errorf("traitx: BaseURL must be an absolute http(s) URL, got %q", c.BaseURL)
	}

	c.APIKey = strings.TrimSpace(c.APIKey)
	if c.APIKey == "" {
		return fmt.Errorf("traitx: APIKey is required")
	}
	if strings.HasPrefix(c.APIKey, "trx_") && !strings.HasPrefix(c.APIKey, "trx_pvk_") {
		return fmt.Errorf("traitx: APIKey looks like a PUBLIC collector key (trx_…); " +
			"the decision SDK needs the PRIVATE key (trx_pvk_…) and must only run server-side")
	}

	if c.Timeout <= 0 {
		c.Timeout = 2500 * time.Millisecond
	}
	switch {
	case c.MaxRetries == 0:
		c.MaxRetries = 2
	case c.MaxRetries == -1:
		c.MaxRetries = 0
	case c.MaxRetries < -1:
		return fmt.Errorf("traitx: MaxRetries must be >= 0, or -1 to disable retries")
	}
	if c.RetryBackoff <= 0 {
		c.RetryBackoff = 100 * time.Millisecond
	}

	if c.FailureMode == "" {
		c.FailureMode = ActionAllow
	}
	if c.ClientErrorMode == "" {
		c.ClientErrorMode = ActionAllow
	}

	if c.Thresholds.Challenge == 0 && c.Thresholds.Deny == 0 {
		c.Thresholds = Thresholds{Challenge: 40, Deny: 70}
	}
	if c.Thresholds.Challenge > c.Thresholds.Deny {
		return fmt.Errorf("traitx: Thresholds.Challenge (%v) must not exceed Thresholds.Deny (%v)",
			c.Thresholds.Challenge, c.Thresholds.Deny)
	}

	if c.Breaker.FailureThreshold <= 0 {
		c.Breaker.FailureThreshold = 5
	}
	if c.Breaker.ResetAfter <= 0 {
		c.Breaker.ResetAfter = 30 * time.Second
	}

	if c.UserAgent == "" {
		c.UserAgent = "traitx-sdk-go/" + Version
	}
	if c.Logger == nil {
		c.Logger = log.New(io.Discard, "", 0)
		if c.Debug {
			c.Logger = log.Default()
		}
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        50,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
			// The per-attempt deadline comes from the request context, not here,
			// so retries each get a full budget.
		}
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	return nil
}

// RedactKey renders a key for logs: "trx_pvk_…a9f3". Never log the full value.
func RedactKey(key string) string {
	if key == "" {
		return "<empty>"
	}
	if len(key) <= 12 {
		cut := len(key)
		if cut > 4 {
			cut = 4
		}
		return key[:cut] + "…"
	}
	return key[:8] + "…" + key[len(key)-4:]
}
