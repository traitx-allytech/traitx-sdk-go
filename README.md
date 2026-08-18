# TraitX Decision SDK — Go

Turns a TraitX risk evaluation into one of three answers: **allow**, **challenge**,
**deny**. Go 1.19+, standard library only.

Wire contract and decision algorithm: [`SPEC.md`](SPEC.md).

---

## Install

```bash
go get github.com/traitx-allytech/traitx-sdk-go
```

---

## Quick start

```go
package main

import (
    "context"
    "log"
    "net/http"
    "os"
    "time"

    traitx "github.com/traitx-allytech/traitx-sdk-go"
)

// One client per process — the circuit breaker lives on the instance, so a client
// per request would never open. Client is safe for concurrent use.
var client = traitx.MustNew(traitx.Config{
    BaseURL:       os.Getenv("TRAITX_BASE_URL"),        // https://traitx.allytech.sa
    APIKey:        os.Getenv("TRAITX_PRIVATE_KEY"),     // trx_pvk_…
    ApplicationID: os.Getenv("TRAITX_APPLICATION_ID"),
    Timeout:       2500 * time.Millisecond,
    FailureMode:   traitx.ActionAllow,                  // TraitX down → do not block logins
})

func login(w http.ResponseWriter, r *http.Request) {
    user, ok := authenticate(r)
    if !ok {
        http.Error(w, "invalid credentials", http.StatusUnauthorized)
        return
    }

    decision, err := client.EvaluateLogin(r.Context(), traitx.Event{
        RequestID: r.Header.Get("X-TraitX-Request-Id"),  // from the browser collector
        User:      &traitx.User{ID: user.ID, Email: user.Email},
        Context:   traitx.ContextFromRequest(r),
    })
    if err != nil {
        log.Printf("traitx: %v", err) // validation bug in this handler
    }

    switch {
    case decision.IsDenied():
        http.Error(w, "access denied", http.StatusForbidden)
    case decision.RequiresChallenge():
        sendOTP(user)
    default:
        issueToken(w, user)
    }
}
```

`RequestID` comes from the browser collector; your frontend passes it to your
backend, which passes it here.

---

## Event helpers

```go
client.EvaluateLogin(ctx, event)
client.EvaluateRegistration(ctx, event)
client.EvaluatePasswordReset(ctx, event)
client.EvaluateProfileUpdate(ctx, event)
client.ReportChallengeOutcome(ctx, event, passed)

client.EvaluateTransaction(ctx, traitx.Event{
    RequestID: requestID,
    User:      &traitx.User{ID: user.ID},
    Context:   traitx.ContextFromRequest(r),
    Attributes: map[string]interface{}{
        "merchant.mcc":    "5967",   // a dotted key is a literal key name
        "payment.channel": "mada",
    },
}, traitx.Transaction{Amount: 5000, Currency: "SAR", PayeeID: "payee_88213"})
```

Anything else goes through `Evaluate` with an explicit `Type`:

```go
decision, err := client.Evaluate(ctx, traitx.Event{
    RequestID:  requestID,
    Type:       traitx.EventCustom,
    Attributes: map[string]interface{}{"promo_code": code},
})
```

### Errors vs decisions

`Evaluate` returns an `error` **only** for an event the SDK refuses to send —
a missing `RequestID`, or `$before_all` used as a type. Those are bugs in calling
code and should fail in your tests.

Network and API failures are not errors. They come back as a `Decision` with
`Degraded: true` and the configured fallback action, so a TraitX outage cannot
take your login or checkout path down.

`MustEvaluate` folds the validation error into a degraded decision, for handlers
that cannot branch on `err`.

---

## Reading a decision

```go
decision.Action            // traitx.ActionAllow | ActionChallenge | ActionDeny ← act on this
decision.Reason            // ReasonPolicyMatch | ReasonShadow | ReasonScoreThreshold | …
decision.Score             // 0–100
decision.RiskLevel         // RiskLevelLow | Medium | High | Critical
decision.Signals           // []string{"bot_behavior", "tor_ip"}
decision.MatchedPolicies   // []MatchedPolicy{{ID, Name, Action, PassThrough}}
decision.Enforced          // false when the deciding policy is shadow-mode
decision.ObservedAction    // what the chain would have done
decision.Degraded          // true when TraitX was unreachable or rejected the call
decision.LatencyMS
decision.Raw               // map[string]interface{} — full response body

decision.IsAllowed()
decision.RequiresChallenge()
decision.IsDenied()
decision.HasDeviceContext() // false → IP enrichment missing, IP policies unreachable
```

Branch on `IsAllowed()`, never on `!IsDenied()` — the latter lets challenges
through unchallenged, which is the most common way this integration goes wrong.

### Shadow mode

A policy deployed with `pass_through: true` evaluates and logs but does not
enforce. The SDK returns `ActionAllow` with `Enforced: false` and
`ObservedAction` set to what would have happened:

```go
if !decision.Enforced && decision.ObservedAction != traitx.ActionAllow {
    log.Printf("traitx shadow would_%s score=%v", decision.ObservedAction, decision.Score)
}
```

---

## Configuration

```go
traitx.Config{
    BaseURL:       "https://traitx.allytech.sa",
    APIKey:        "trx_pvk_…",
    ApplicationID: "ccf2d2a0-…",

    Timeout:      2500 * time.Millisecond, // per attempt
    MaxRetries:   2,                       // 0 = default (2); -1 = no retries
    RetryBackoff: 100 * time.Millisecond,

    FailureMode:     traitx.ActionAllow,
    ClientErrorMode: traitx.ActionAllow,

    Thresholds:         traitx.Thresholds{Challenge: 40, Deny: 70},
    DenyOnSignals:      []string{"headless_browser"},
    ChallengeOnSignals: []string{"new_device"},

    EnforceShadowDecisions: false,

    Breaker: traitx.BreakerConfig{FailureThreshold: 5, ResetAfter: 30 * time.Second},

    Debug:      false,
    Logger:     log.Default(),
    HTTPClient: myInstrumentedClient,   // optional
    OnDecision: func(d traitx.Decision) *traitx.Decision { return nil },
}
```

`MaxRetries: 0` means "use the default", because that is the zero value of the
struct. Pass `-1` to disable retries.

Worst-case latency is `Timeout × (MaxRetries + 1)` plus backoff — about 7.5 s
with the defaults. Lower `Timeout` on latency-critical paths, and pass a
`context.Context` with your own deadline: the SDK honours it and stops retrying.

---

## Management API (optional)

Policies and lists authenticate with a **portal JWT**, not the private key. These
calls return errors rather than degrading.

```go
client.Management.WithToken(os.Getenv("TRAITX_PORTAL_JWT"))

audit, err := client.Management.AuditPolicies(ctx, "")
log.Printf("traitx: %d live, %d shadow, %d disabled",
    len(audit.Live), len(audit.Shadow), len(audit.Disabled))

expires := time.Now().Add(90 * 24 * time.Hour)
_, err = client.Management.AddEntry(ctx, blockedDevicesListID, traitx.NewEntry{
    Value:     visitorID,
    Comment:   "chargeback " + caseID,
    ExpiresAt: &expires,
})
```

---

## Self-check

```bash
TRAITX_BASE_URL=https://traitx.allytech.sa \
TRAITX_PRIVATE_KEY=trx_pvk_… \
TRAITX_APPLICATION_ID=ccf2d2a0-… \
go run ./cmd/doctor req_abc123
```

## Tests

```bash
go test ./...
```

`conformance_test.go` runs [`conformance/vectors.json`](conformance/vectors.json),
the shared fixture every language binding must satisfy.

## Example

[`example/main.go`](example/main.go) — a `net/http` service with login,
OTP callback, transfer and a health route that exposes the breaker state.
