// A minimal net/http service showing the login, OTP-callback and transfer paths.
//
//	TRAITX_BASE_URL=https://traitx.allytech.sa \
//	TRAITX_PRIVATE_KEY=trx_pvk_... \
//	go run ./example
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	traitx "github.com/traitx-allytech/traitx-sdk-go"
)

// One client per process. The circuit breaker lives on the instance, so a client
// per request would never open.
var client = traitx.MustNew(traitx.Config{
	BaseURL:       os.Getenv("TRAITX_BASE_URL"),
	APIKey:        os.Getenv("TRAITX_PRIVATE_KEY"),
	ApplicationID: os.Getenv("TRAITX_APPLICATION_ID"),
	Timeout:       2500 * time.Millisecond,
	// TraitX unreachable must not block logins. Make the opposite choice
	// deliberately if your risk appetite calls for it.
	FailureMode:     traitx.ActionAllow,
	ClientErrorMode: traitx.ActionAllow,
})

func main() {
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/verify-otp", handleVerifyOTP)
	http.HandleFunc("/api/transfer", handleTransfer)
	http.HandleFunc("/healthz", handleHealth)

	log.Println("listening on :8000")
	log.Fatal(http.ListenAndServe(":8000", nil))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	// Authenticate first: TraitX decides whether to trust a *successful* login,
	// and sending the event before you know that muddies the signal.
	user, ok := authenticate(body.Email, body.Password)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	decision, err := client.EvaluateLogin(r.Context(), traitx.Event{
		RequestID: r.Header.Get("X-TraitX-Request-Id"),
		User:      &traitx.User{ID: user.ID, Email: user.Email},
		Context:   traitx.ContextFromRequest(r),
	})
	if err != nil {
		// A validation error is a bug in this handler, not a risk signal.
		log.Printf("traitx: %v", err)
		writeJSON(w, http.StatusOK, map[string]string{"token": issueToken(user)})
		return
	}

	log.Printf("traitx login user=%s %s policies=%d",
		user.ID, decision, len(decision.MatchedPolicies))

	switch {
	case decision.IsDenied():
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":     "access denied",
			"reference": decision.RequestID,
		})
	case decision.RequiresChallenge():
		sendOTP(user)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"next":    "otp",
			"signals": decision.Signals,
		})
	default:
		writeJSON(w, http.StatusOK, map[string]string{"token": issueToken(user)})
	}
}

func handleVerifyOTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UserID string `json:"user_id"`
		Code   string `json:"code"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	passed := body.Code == "123456"

	// Close the loop so $challenge policies can react to repeated failures.
	if _, err := client.ReportChallengeOutcome(r.Context(), traitx.Event{
		RequestID: r.Header.Get("X-TraitX-Request-Id"),
		User:      &traitx.User{ID: body.UserID},
		Context:   traitx.ContextFromRequest(r),
	}, passed); err != nil {
		log.Printf("traitx: %v", err)
	}

	if !passed {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid code"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": "…"})
}

func handleTransfer(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UserID  string  `json:"user_id"`
		Amount  float64 `json:"amount"`
		PayeeID string  `json:"payee_id"`
		Channel string  `json:"channel"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	decision := client.MustEvaluate(r.Context(), traitx.Event{
		RequestID: r.Header.Get("X-TraitX-Request-Id"),
		Type:      traitx.EventTransaction,
		User:      &traitx.User{ID: body.UserID},
		Context:   traitx.ContextFromRequest(r),
		Attributes: map[string]interface{}{
			"amount":   body.Amount,
			"currency": "SAR",
			"payee_id": body.PayeeID,
			// A dotted key is a literal key name, not a nested object.
			"payment.channel": body.Channel,
		},
	})

	switch {
	case decision.IsDenied():
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":     "transfer blocked",
			"reference": decision.RequestID,
		})
	case decision.RequiresChallenge():
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"next":  "3ds",
			"score": decision.Score,
		})
	default:
		writeJSON(w, http.StatusOK, map[string]string{"status": "submitted"})
	}
}

// handleHealth surfaces the breaker so your own monitoring can see a TraitX outage.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"traitx_breaker":   client.BreakerState(),
		"traitx_reachable": client.Health(ctx),
	})
}

// --- stand-ins for your real application ------------------------------------

type account struct {
	ID    string
	Email string
}

func authenticate(email, password string) (account, bool) {
	if password == "" {
		return account{}, false
	}
	return account{ID: "usr_1", Email: email}, true
}

func sendOTP(user account)           { log.Printf("otp sent to %s", user.Email) }
func issueToken(user account) string { return "token-for-" + user.ID }

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
