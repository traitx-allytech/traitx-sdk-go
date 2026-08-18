# TraitX Decision SDK — Wire Specification

Version `1.0.0` · normative for every language binding under `sdk/`.

This document is the single source of truth. If a language SDK disagrees with this
document, the SDK is wrong.

---

## 1. What the SDK does

The TraitX platform has two halves:

| Half | Runs where | Talks to | Key |
| --- | --- | --- | --- |
| **Collector** (`traitx.esm.js`) | End user's browser | `POST /api/v1/fingerprint` | **public** key `trx_…` |
| **Decision SDK** (this) | Your backend | `POST /api/v1/risk` | **private** key `trx_pvk_…` |

The browser collector produces a `requestId`. Your backend passes that `requestId`
to the Risk API together with the business event (login, transaction, …). The Risk
API evaluates the tenant's policy chain for that event group and returns a score,
a signal list and — when a policy matched — an action.

The SDK's job is to turn that response into exactly one of three answers:

```
ALLOW      let the request through
CHALLENGE  step up — OTP, 3-DS, CAPTCHA, manual review
DENY       block the request
```

…and to never take your login or checkout path down when TraitX is slow or
unreachable.

---

## 2. Endpoints

Base URL is the tenant deployment, e.g. `https://traitx.allytech.sa`.

| Method | Path | Auth header | Purpose |
| --- | --- | --- | --- |
| `POST` | `/api/v1/risk` | `X-API-Key: trx_pvk_…` | Evaluate an event → decision |
| `GET` | `/api/v1/fingerprint/{requestId}` | `X-API-Key: trx_pvk_…` | Full device fingerprint |
| `POST` | `/api/v1/fingerprint` | `X-API-Key: trx_…` (public) | Collector ingest — browser only |
| `GET` | `/health` | none | Liveness, returns `healthy` |

Management (portal API, **bearer JWT**, not the private key):

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/policies` | List policies for an application |
| `GET` | `/api/v1/policies/{id}` | Read one policy |
| `PATCH` | `/api/v1/policies/{id}/enable` \| `/disable` | Toggle enforcement |
| `PATCH` | `/api/v1/policies/{id}/pass-through/enable` \| `/disable` | Toggle shadow mode |
| `GET` | `/api/v1/lists` | List lists |
| `POST` | `/api/v1/lists/{id}/entries` | Add one entry |
| `POST` | `/api/v1/lists/{id}/entries/bulk` | Add up to 1000 entries |

Management calls carry `Authorization: Bearer <jwt>` and — because policies and
lists are **application-scoped** — `X-Application-ID: <uuid>`. Omitting the
application header makes the API fall back to the tenant's oldest active
application, which is almost never what you want.

### 2.1 Error envelope

Non-2xx responses use:

```json
{ "error": "Unauthorized", "message": "Invalid or expired API key" }
```

Observed status codes: `401` missing/invalid key, `400` malformed body,
`429` rate limited, `5xx` upstream failure.

---

## 3. Risk request

`POST /api/v1/risk`

```json
{
  "request_id": "req_9f3c1a7b22",
  "type": "$login",
  "status": "$succeeded",
  "created_at": "2026-08-08T16:04:11.204Z",
  "session": {
    "id": "sess_3f9ac2",
    "created_at": "2026-08-08T15:58:00.000Z"
  },
  "context": {
    "ip": "66.118.160.25",
    "headers": [
      ["User-Agent", "Mozilla/5.0 (Macintosh; …) Chrome/120.0"],
      ["Accept-Language", "ar-SA,ar;q=0.9,en;q=0.8"],
      ["X-Forwarded-For", "66.118.160.25"]
    ]
  },
  "user": {
    "id": "usr_10231",
    "email": "sara@example.com",
    "name": "Sara A.",
    "phone": "+9665…",
    "registered_at": "2025-02-11T09:12:00Z",
    "address": { "country_code": "SA", "city": "Ta'if" }
  },
  "amount": 5000,
  "currency": "SAR",
  "payee_id": "payee_88213"
}
```

### 3.1 Field rules

| Field | Required | Notes |
| --- | --- | --- |
| `request_id` | yes | From the browser collector's `get()` result. Without it the request has no device context and `ip_enrichment.*` / `threats.*` policies cannot match. |
| `type` | yes | Event group, §4. |
| `status` | yes | `$succeeded` or `$failed`. |
| `created_at` | yes | RFC 3339 / ISO 8601 UTC with milliseconds. |
| `session.id` | recommended | Your session identifier. |
| `session.created_at` | recommended | RFC 3339. |
| `context.ip` | **yes in practice** | The **end user's** IP, never your server's. |
| `context.headers` | recommended | Array of `[name, value]` **pairs**, not an object. Forward the end user's `User-Agent`, `Accept-Language`, `X-Forwarded-For`, `Referer`. |
| `user.*` | recommended | Whatever you hold. `id` and `email` drive the identity policies. |
| *anything else* | optional | Merged into the event root as custom attributes. |

**`context.headers` is an array of pairs by design.** Headers can legitimately
repeat, and the policy engine matches on ordered pairs. Serialising it as a JSON
object is the single most common integration bug.

### 3.2 Custom attributes

Transaction and business fields are sent at the **event root**, not nested:

```json
{ "amount": 5000, "currency": "SAR", "merchant.mcc": "5967", "payment.channel": "mada" }
```

A key containing a dot is a literal key whose name happens to contain a dot — it
is *not* a nested object. Policy triggers address it with the same dotted path.

Every SDK exposes `.attribute(key, value)` / `attributes = {...}` for these and
must not attempt to nest them.

---

## 4. Event groups

Mirrors `models/policy.go` `PolicyEventGroup`.

| Constant | Wire value | Use for |
| --- | --- | --- |
| `LOGIN` | `$login` | Authentication attempt |
| `REGISTRATION` | `$registration` | Signup |
| `LOGOUT` | `$logout` | Session end |
| `TRANSACTION` | `$transaction` | Payment, transfer, withdrawal |
| `CHALLENGE` | `$challenge` | Outcome of a step-up you issued |
| `PROFILE` | `$profile` | Profile view |
| `PROFILE_UPDATE` | `$profile_update` | Email/phone/address change |
| `PROFILE_RESET` | `$profile_reset` | Profile reset |
| `PASSWORD_RESET_REQUEST` | `$password_reset_request` | Recovery flow entry |
| `CUSTOM` | `$custom` | Your own event |
| `GENERIC` | `$generic` | Uncategorised |

`$before_all` and `$after_all` are **chain hooks**, not event types. Policies in
those groups run on every event. Never send them as `type`; the API has no
standalone event to attach them to. SDKs must reject them with a client-side
validation error naming the concrete group to use instead.

---

## 5. Risk response

```json
{
  "score": 88.0,
  "signals": ["bot_behavior", "tor_ip", "high_activity_device"],
  "policy": {
    "action": "deny",
    "matched": [
      { "id": "b1f0…", "name": "CY7 Known Bot User-Agent", "action": "deny", "pass_through": true }
    ]
  },
  "debug": {
    "abuse_ip": { "reason": "no_enrichment_data" },
    "bot_behavior": { "risk_score": 85, "details": "Automated form filling detected" }
  }
}
```

### 5.1 Tolerant parsing (normative)

The deployment has evolved; SDKs must accept all of these spellings and must
never throw on an unexpected shape.

| Concept | Accepted locations, in order |
| --- | --- |
| Chain action | `policy.action`, `policy.decision`, `decision.action`, `decision`, `action` |
| Matched policies | `policy.matched`, `policy.matched_policies`, `matched_policies`, `policy.hits` |
| Score | `score`, `risk_score`, `data.riskScore` |
| Signals | `signals`, `risk_signals`, `data.signals` |
| Per-policy shadow flag | `pass_through`, `passThrough`, `shadow`, `pass_through_mode` |
| Per-policy action | `action`, `inline_action`, `inlineAction` |
| Per-policy id / name | `id`, `policy_id` / `name`, `policy_name` |

Action strings are matched case-insensitively after trimming an optional leading
`$`. `block` is an accepted alias for `deny`; `stepup` and `step_up` for
`challenge`; `pass` and `accept` for `allow`. Anything unrecognised is treated as
*absent*, not as allow.

The complete decoded body is always exposed as `decision.raw` so callers can read
fields this spec has not pinned down yet.

---

## 6. Decision resolution algorithm (normative)

Given the HTTP outcome and the parsed response, produce exactly one `Action`.
Steps are evaluated in order; the first that applies wins.

```
1. TRANSPORT FAILURE
   Timeout, connection error, 5xx after retries, 429 after retries,
   an open circuit breaker, or a 2xx whose body is not decodable JSON
   (a proxy error page served with status 200 is a transport failure,
   not a risk verdict).
     action  = config.failureMode          (default ALLOW)
     reason  = DEGRADED
     degraded = true
     error   = <message>
   STOP.

2. CLIENT ERROR (400, 401, 403, 422)
   A misconfigured key or a malformed payload is an engineering fault,
   not a risk signal.
     action  = config.clientErrorMode      (default ALLOW)
     reason  = CLIENT_ERROR
     degraded = true
   STOP.
   Rationale: a rotated key must not lock every customer out of checkout.
   Set clientErrorMode = DENY only if you would rather fail closed.

3. POLICY CHAIN ACTION PRESENT
     observedAction = parsed chain action
     enforced       = NOT shadowed(matched policies)          -- §6.1
     action         = enforced ? observedAction : ALLOW
     reason         = enforced ? POLICY_MATCH : SHADOW
   STOP.

4. NO CHAIN ACTION — derive from score and signals
     a = ALLOW
     if score >= thresholds.deny        -> a = DENY
     else if score >= thresholds.challenge -> a = CHALLENGE
     reason = (a != ALLOW) ? SCORE_THRESHOLD : NO_MATCH

     s = ALLOW
     if any signal in config.denyOnSignals      -> s = DENY
     else if any signal in config.challengeOnSignals -> s = CHALLENGE

     if severity(s) > severity(a):
        a = s ; reason = SIGNAL_OVERRIDE

     action = a
   STOP.
```

`severity(ALLOW) = 0 < severity(CHALLENGE) = 1 < severity(DENY) = 2`.

Signal and threshold rules are deliberately **not** applied when the policy chain
returned an action. The policy chain is the configured control plane; a local
threshold must not override an explicit allowlist bypass. Post-process with the
`onDecision` hook if you need business rules on top.

### 6.1 Shadow mode (`pass_through`)

A policy deployed with `pass_through: true` evaluates and logs but must not
enforce. `shadowed(matched)` is true when **every** matched policy that carries
the chain's action is flagged pass-through. If no matched policy exposes a
pass-through flag, `shadowed` is **false** — the server is the authority and the
SDK assumes it already withheld the action if it meant to.

When `shadowed` is true the SDK returns `ALLOW` with `enforced = false` and
`observedAction` set to what would have happened. Set
`config.enforceShadowDecisions = true` to enforce anyway (useful in staging).

### 6.2 Risk level

Derived from score, purely informational:

| Level | Score |
| --- | --- |
| `low` | `< 30` |
| `medium` | `30 – 59` |
| `high` | `60 – 79` |
| `critical` | `>= 80` |

Thresholds come from the collector's own `RiskThresholds` (low 30, medium 60,
high 80, critical 90 — the SDK collapses `>= 80` into `critical`). They are
independent of the decision thresholds in step 4.

---

## 7. Decision object

Every SDK returns a value with these members (naming adapted to the language's
convention — `snake_case` in Python/PHP, `camelCase` in JS/Java/C#, exported
fields in Go):

| Member | Type | Meaning |
| --- | --- | --- |
| `action` | `Action` | `allow` \| `challenge` \| `deny` — the answer to act on |
| `observed_action` | `Action?` | What the chain said, even when not enforced |
| `enforced` | `bool` | `false` when the deciding policy was shadow-mode |
| `reason` | `Reason` | `policy_match`, `shadow`, `score_threshold`, `signal_override`, `no_match`, `degraded`, `client_error` |
| `score` | `float` | 0–100, `0` when unavailable |
| `risk_level` | `RiskLevel` | §6.2 |
| `signals` | `[]string` | Fraud signals |
| `matched_policies` | `[]MatchedPolicy` | `{id, name, action, event_group, pass_through}` |
| `degraded` | `bool` | Decision did not come from a healthy evaluation |
| `error` | `string?` | Populated when degraded |
| `status_code` | `int` | HTTP status, `0` on transport failure |
| `request_id` | `string` | Echo of the collector `request_id` |
| `latency_ms` | `int` | Wall-clock of the call, including retries |
| `raw` | `map` | Full decoded body |

Convenience predicates, present in every SDK:
`is_allowed()`, `requires_challenge()`, `is_denied()`.

`is_allowed()` is true only for `action == allow`. Do **not** write
`if (!decision.isDenied())` — that lets challenges through unchallenged.

---

## 8. Configuration

| Option | Default | Notes |
| --- | --- | --- |
| `base_url` | — | Required. Trailing slash trimmed. |
| `api_key` | — | Required. Private key `trx_pvk_…`. |
| `application_id` | `null` | Sent as `X-Application-ID` when set. Required for management calls. |
| `timeout_ms` | `2500` | Per attempt, connect + read. |
| `max_retries` | `2` | Extra attempts after the first. |
| `retry_backoff_ms` | `100` | Base for exponential backoff with full jitter. |
| `failure_mode` | `allow` | Step 1 outcome. |
| `client_error_mode` | `allow` | Step 2 outcome. |
| `thresholds.challenge` | `40` | Step 4. |
| `thresholds.deny` | `70` | Step 4. |
| `deny_on_signals` | `[]` | Step 4 escalation. |
| `challenge_on_signals` | `[]` | Step 4 escalation. |
| `enforce_shadow_decisions` | `false` | §6.1. |
| `breaker.failure_threshold` | `5` | Consecutive transport failures before opening. |
| `breaker.reset_after_ms` | `30000` | Half-open probe delay. |
| `user_agent` | `traitx-sdk-<lang>/<ver>` | Sent as `User-Agent`. |
| `debug` | `false` | Log requests/responses with the key redacted. |
| `on_decision` | `null` | Hook `(decision) -> Decision?`; return a replacement or nothing. |

Validation at construction time: `base_url` must be a non-empty absolute
`http`/`https` URL; `api_key` must be non-empty. A key starting with `trx_` but
not `trx_pvk_` is a **public** key and must be rejected — sending the public key
to `/api/v1/risk` returns 401 and, worse, publishing the private key to a browser
is the failure this check exists to prevent.

Never log `api_key`. Debug output renders it as `trx_pvk_…` + last 4 characters.

---

## 9. Retry policy

Retry only when a retry can plausibly succeed and the request is safe to repeat.
`POST /api/v1/risk` is treated as idempotent for a given `request_id`.

| Condition | Retry |
| --- | --- |
| Connection error, DNS failure, TLS error | yes |
| Timeout | yes |
| `408`, `429`, `500`, `502`, `503`, `504` | yes |
| Any other 4xx | no |
| 2xx | no |

Delay before attempt *n* (1-based, after the first attempt):

```
delay = random(0, retry_backoff_ms * 2^(n-1))        full jitter
```

If a `Retry-After` header is present and parses to seconds or an HTTP date, it
overrides the computed delay, capped at 5000 ms so a retry never blows the
caller's own request budget.

The **total** time spent must stay bounded: `timeout_ms * (max_retries + 1)` plus
backoff. With defaults that is ~7.5 s worst case — document it, and lower
`timeout_ms` on latency-critical paths.

---

## 10. Circuit breaker

Per client instance, counting **transport failures only** (steps 1, never step 2
or a successful evaluation).

```
CLOSED   → after failure_threshold consecutive failures → OPEN
OPEN     → all calls short-circuit to step 1 without touching the network
         → after reset_after_ms → HALF_OPEN
HALF_OPEN→ one probe call allowed
         → success → CLOSED (counter reset)
         → failure → OPEN (timer reset)
```

A short-circuited call returns `reason = DEGRADED`, `error = "circuit breaker
open"`, `latency_ms ≈ 0`. This is the difference between one slow dependency and
a queue of 2.5-second waits on every login.

---

## 11. Conformance vectors

`sdk/conformance/vectors.json` holds the canonical inputs and expected outputs
for §6. Every SDK ships a test that loads that file and asserts on it. A binding
that does not pass the vectors is not conformant.

Vector shape:

```json
{
  "name": "shadow policy is observed but not enforced",
  "config": { "failureMode": "allow", "thresholds": { "challenge": 40, "deny": 70 } },
  "http": { "status": 200, "body": { "score": 88, "policy": { "action": "deny",
            "matched": [ { "id": "p1", "name": "CY7", "pass_through": true } ] } } },
  "expect": { "action": "allow", "observedAction": "deny", "enforced": false,
              "reason": "shadow", "riskLevel": "critical" }
}
```

---

## 12. Threat model and non-goals

* The private key authorises risk evaluation for the whole tenant. It belongs in
  a server-side secret store. Any SDK API that would encourage shipping it to a
  browser is out of scope by design — that is why there is no browser build of
  the decision SDK, only the collector.
* The SDK does not cache decisions. A device's risk changes between events, and a
  cached `allow` is a bypass primitive.
* The SDK does not itself enforce anything. It returns an `Action`; wiring that
  to your auth or payment flow is your application's job, and it must fail
  closed on `DENY` in code you control.
* `request_id` is attacker-supplied when it arrives from a browser. Treat a
  missing or unknown `request_id` as "no device context" — the Risk API will
  return a response with empty enrichment rather than an error, and your policies
  will silently not match. §13 covers detecting that.

---

## 13. Detecting a broken integration

A silently non-matching policy looks identical to a clean user. Two checks:

1. `debug.abuse_ip.reason == "no_enrichment_data"` in the response means no IP
   enrichment was attached, so every `ip_enrichment.*` trigger is unreachable.
   The SDKs surface this as `decision.has_device_context() == false`.
2. If `matched_policies` is empty for an event group you know has enabled
   policies, either the `request_id` never reached the collector, the
   `application_id` on the key differs from the one holding the policies, or the
   trigger field path does not exist in the event.

Run `sdk/<lang>` self-check (`traitx doctor` in the Node CLI,
`python -m traitx.doctor`, `go run ./cmd/doctor`) against a real key to confirm
connectivity, key class, application scoping and enrichment in one shot.
