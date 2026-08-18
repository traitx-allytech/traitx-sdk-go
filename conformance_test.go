package traitx

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// Runs sdk/conformance/vectors.json against the Go decision engine.
//
//	cd sdk/go && go test ./...
//
// Every language SDK ships the equivalent of this file. If a vector fails here
// but passes elsewhere, the bindings have drifted.

type vectorHTTP struct {
	Status         int                    `json:"status"`
	Body           map[string]interface{} `json:"body"`
	RawBody        *string                `json:"rawBody"`
	TransportError string                 `json:"transportError"`
}

type vectorExpect struct {
	Action           string   `json:"action"`
	ObservedAction   *string  `json:"observedAction"`
	Enforced         *bool    `json:"enforced"`
	Reason           string   `json:"reason"`
	Score            *float64 `json:"score"`
	RiskLevel        string   `json:"riskLevel"`
	Degraded         *bool    `json:"degraded"`
	StatusCode       *int     `json:"statusCode"`
	MatchedCount     *int     `json:"matchedCount"`
	FirstMatchedID   *string  `json:"firstMatchedId"`
	FirstMatchedName *string  `json:"firstMatchedName"`
	HasError         *bool    `json:"hasError"`
	HasDeviceContext *bool    `json:"hasDeviceContext"`
}

type vectorConfig struct {
	FailureMode            string   `json:"failureMode"`
	ClientErrorMode        string   `json:"clientErrorMode"`
	DenyOnSignals          []string `json:"denyOnSignals"`
	ChallengeOnSignals     []string `json:"challengeOnSignals"`
	EnforceShadowDecisions *bool    `json:"enforceShadowDecisions"`
	Thresholds             *struct {
		Challenge *float64 `json:"challenge"`
		Deny      *float64 `json:"deny"`
	} `json:"thresholds"`
}

type vector struct {
	Name   string       `json:"name"`
	Config vectorConfig `json:"config"`
	HTTP   vectorHTTP   `json:"http"`
	Expect vectorExpect `json:"expect"`
}

type vectorSuite struct {
	Defaults struct {
		Config vectorConfig `json:"config"`
	} `json:"defaults"`
	Vectors []vector `json:"vectors"`
}

// locateVectors walks up from the working directory looking for the shared fixture,
// so the suite passes whether this package sits in the monorepo or at the root of
// its own repository.
func locateVectors(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("could not determine working directory: %v", err)
	}
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, "conformance", "vectors.json")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not find conformance/vectors.json")
	return ""
}

func loadSuite(t *testing.T) vectorSuite {
	t.Helper()
	path := locateVectors(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read %s: %v", path, err)
	}
	var suite vectorSuite
	if err := json.Unmarshal(raw, &suite); err != nil {
		t.Fatalf("could not parse %s: %v", path, err)
	}
	if len(suite.Vectors) == 0 {
		t.Fatalf("%s contains no vectors", path)
	}
	return suite
}

func configFor(t *testing.T, defaults, overrides vectorConfig) Config {
	t.Helper()

	pick := func(override, fallback string) string {
		if override != "" {
			return override
		}
		return fallback
	}

	thresholds := Thresholds{Challenge: 40, Deny: 70}
	if defaults.Thresholds != nil {
		if defaults.Thresholds.Challenge != nil {
			thresholds.Challenge = *defaults.Thresholds.Challenge
		}
		if defaults.Thresholds.Deny != nil {
			thresholds.Deny = *defaults.Thresholds.Deny
		}
	}
	if overrides.Thresholds != nil {
		if overrides.Thresholds.Challenge != nil {
			thresholds.Challenge = *overrides.Thresholds.Challenge
		}
		if overrides.Thresholds.Deny != nil {
			thresholds.Deny = *overrides.Thresholds.Deny
		}
	}

	enforceShadow := false
	if defaults.EnforceShadowDecisions != nil {
		enforceShadow = *defaults.EnforceShadowDecisions
	}
	if overrides.EnforceShadowDecisions != nil {
		enforceShadow = *overrides.EnforceShadowDecisions
	}

	denySignals := defaults.DenyOnSignals
	if overrides.DenyOnSignals != nil {
		denySignals = overrides.DenyOnSignals
	}
	challengeSignals := defaults.ChallengeOnSignals
	if overrides.ChallengeOnSignals != nil {
		challengeSignals = overrides.ChallengeOnSignals
	}

	cfg := Config{
		BaseURL:                "https://example.test",
		APIKey:                 "trx_pvk_conformance_key_0000",
		FailureMode:            Action(pick(overrides.FailureMode, defaults.FailureMode)),
		ClientErrorMode:        Action(pick(overrides.ClientErrorMode, defaults.ClientErrorMode)),
		Thresholds:             thresholds,
		DenyOnSignals:          denySignals,
		ChallengeOnSignals:     challengeSignals,
		EnforceShadowDecisions: enforceShadow,
	}
	if err := cfg.applyDefaults(); err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

func outcomeFor(h vectorHTTP) HTTPOutcome {
	if h.TransportError != "" {
		return HTTPOutcome{StatusCode: 0, LatencyMS: 3, TransportError: h.TransportError}
	}
	if h.RawBody != nil {
		// A body that is not decodable JSON reaches the engine undecoded.
		return HTTPOutcome{StatusCode: h.Status, LatencyMS: 3, BodyDecoded: false}
	}
	outcome := HTTPOutcome{
		StatusCode:  h.Status,
		Body:        h.Body,
		BodyDecoded: true,
		LatencyMS:   3,
	}
	if h.Status >= 500 || h.Status == 429 || h.Status == 408 {
		outcome.TransportError = "risk api returned HTTP " + strconv.Itoa(h.Status)
	}
	return outcome
}

func TestConformanceVectors(t *testing.T) {
	suite := loadSuite(t)

	for _, v := range suite.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			cfg := configFor(t, suite.Defaults.Config, v.Config)
			got := ResolveDecision(outcomeFor(v.HTTP), cfg, "req_conformance")

			if string(got.Action) != v.Expect.Action {
				t.Errorf("action = %q, want %q", got.Action, v.Expect.Action)
			}
			if v.Expect.ObservedAction != nil {
				if string(got.ObservedAction) != *v.Expect.ObservedAction {
					t.Errorf("observedAction = %q, want %q", got.ObservedAction, *v.Expect.ObservedAction)
				}
			}
			if v.Expect.Enforced != nil && got.Enforced != *v.Expect.Enforced {
				t.Errorf("enforced = %v, want %v", got.Enforced, *v.Expect.Enforced)
			}
			if v.Expect.Reason != "" && string(got.Reason) != v.Expect.Reason {
				t.Errorf("reason = %q, want %q", got.Reason, v.Expect.Reason)
			}
			if v.Expect.Score != nil && got.Score != *v.Expect.Score {
				t.Errorf("score = %v, want %v", got.Score, *v.Expect.Score)
			}
			if v.Expect.RiskLevel != "" && string(got.RiskLevel) != v.Expect.RiskLevel {
				t.Errorf("riskLevel = %q, want %q", got.RiskLevel, v.Expect.RiskLevel)
			}
			if v.Expect.Degraded != nil && got.Degraded != *v.Expect.Degraded {
				t.Errorf("degraded = %v, want %v", got.Degraded, *v.Expect.Degraded)
			}
			if v.Expect.StatusCode != nil && got.StatusCode != *v.Expect.StatusCode {
				t.Errorf("statusCode = %d, want %d", got.StatusCode, *v.Expect.StatusCode)
			}
			if v.Expect.MatchedCount != nil && len(got.MatchedPolicies) != *v.Expect.MatchedCount {
				t.Errorf("len(matchedPolicies) = %d, want %d",
					len(got.MatchedPolicies), *v.Expect.MatchedCount)
			}
			if v.Expect.FirstMatchedID != nil {
				if len(got.MatchedPolicies) == 0 {
					t.Fatalf("expected a matched policy, got none")
				}
				if got.MatchedPolicies[0].ID != *v.Expect.FirstMatchedID {
					t.Errorf("matchedPolicies[0].ID = %q, want %q",
						got.MatchedPolicies[0].ID, *v.Expect.FirstMatchedID)
				}
			}
			if v.Expect.FirstMatchedName != nil {
				if len(got.MatchedPolicies) == 0 {
					t.Fatalf("expected a matched policy, got none")
				}
				if got.MatchedPolicies[0].Name != *v.Expect.FirstMatchedName {
					t.Errorf("matchedPolicies[0].Name = %q, want %q",
						got.MatchedPolicies[0].Name, *v.Expect.FirstMatchedName)
				}
			}
			if v.Expect.HasError != nil && (got.Error != "") != *v.Expect.HasError {
				t.Errorf("error present = %v (%q), want %v",
					got.Error != "", got.Error, *v.Expect.HasError)
			}
			if v.Expect.HasDeviceContext != nil &&
				got.HasDeviceContext() != *v.Expect.HasDeviceContext {
				t.Errorf("HasDeviceContext() = %v, want %v",
					got.HasDeviceContext(), *v.Expect.HasDeviceContext)
			}

			// Invariants that hold for every vector.
			switch got.Action {
			case ActionAllow, ActionChallenge, ActionDeny:
			default:
				t.Errorf("action %q is not a valid Action", got.Action)
			}
			if got.IsAllowed() != (got.Action == ActionAllow) {
				t.Error("IsAllowed() disagrees with Action")
			}
			if got.IsAllowed() && got.IsDenied() {
				t.Error("a decision cannot be both allowed and denied")
			}
		})
	}
}

func TestEveryReasonIsExercised(t *testing.T) {
	suite := loadSuite(t)
	seen := map[string]bool{}
	for _, v := range suite.Vectors {
		seen[v.Expect.Reason] = true
	}
	for _, reason := range []string{
		"policy_match", "shadow", "score_threshold", "signal_override",
		"no_match", "degraded", "client_error",
	} {
		if !seen[reason] {
			t.Errorf("no vector exercises reason %q", reason)
		}
	}
}
