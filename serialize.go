package traitx

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// chainHooks are policy chain hooks, not event types. See SPEC.md §4.
var chainHooks = map[EventType]bool{"$before_all": true, "$after_all": true}

// reservedRootKeys are fields the SDK owns; a custom attribute may not shadow them.
var reservedRootKeys = map[string]bool{
	"request_id": true, "type": true, "status": true, "created_at": true,
	"session": true, "context": true, "user": true,
}

var knownEventTypes = []EventType{
	EventLogin, EventRegistration, EventLogout, EventTransaction, EventChallenge,
	EventProfile, EventProfileUpdate, EventProfileReset, EventPasswordResetRequest,
	EventCustom, EventGeneric,
}

// interestingHeaders are worth forwarding from an inbound request.
var interestingHeaders = []string{
	"User-Agent", "Accept-Language", "Accept", "Referer", "X-Forwarded-For",
}

// ValidateEvent rejects events the SDK will not send.
func ValidateEvent(event Event) error {
	eventType := EventType(strings.TrimSpace(string(event.Type)))
	if eventType == "" {
		return fmt.Errorf("traitx: Event.Type is required, e.g. traitx.EventLogin")
	}
	if chainHooks[eventType] {
		return fmt.Errorf("traitx: %q is a policy chain hook, not an event type — it runs "+
			"automatically on every event; send the concrete group instead "+
			"(traitx.EventLogin, traitx.EventTransaction, …)", eventType)
	}
	if !strings.HasPrefix(string(eventType), "$") {
		names := make([]string, 0, len(knownEventTypes))
		for _, t := range knownEventTypes {
			names = append(names, string(t))
		}
		return fmt.Errorf("traitx: Event.Type must be a policy event group starting with %q, "+
			"got %q; known groups: %s", "$", eventType, strings.Join(names, ", "))
	}
	if strings.TrimSpace(event.RequestID) == "" {
		return fmt.Errorf("traitx: Event.RequestID is required — it is the requestId returned " +
			"by the browser collector's get(); without it the event carries no device context " +
			"and device/IP policies cannot match")
	}
	for key := range event.Attributes {
		if reservedRootKeys[key] {
			return fmt.Errorf("traitx: attribute %q collides with a reserved root field; "+
				"use a different name", key)
		}
	}
	return nil
}

// SerializeEvent builds the JSON body for POST /api/v1/risk. See SPEC.md §3.
func SerializeEvent(event Event, now time.Time) (map[string]interface{}, error) {
	if err := ValidateEvent(event); err != nil {
		return nil, err
	}

	status := event.Status
	if status == "" {
		status = StatusSucceeded
	}

	createdAt := now
	if event.CreatedAt != nil {
		createdAt = *event.CreatedAt
	}

	payload := map[string]interface{}{
		"request_id": strings.TrimSpace(event.RequestID),
		"type":       string(event.Type),
		"status":     string(status),
		"created_at": isoTime(createdAt),
	}

	if event.Session != nil {
		session := map[string]interface{}{}
		putString(session, "id", event.Session.ID)
		putTime(session, "created_at", event.Session.CreatedAt)
		if len(session) > 0 {
			payload["session"] = session
		}
	}

	if event.Context != nil {
		reqContext := map[string]interface{}{}
		putString(reqContext, "ip", event.Context.IP)
		if len(event.Context.Headers) > 0 {
			// Pairs, not an object — see SPEC.md §3.1.
			headers := make([][]string, 0, len(event.Context.Headers))
			for _, pair := range event.Context.Headers {
				headers = append(headers, []string{pair[0], pair[1]})
			}
			reqContext["headers"] = headers
		}
		if len(reqContext) > 0 {
			payload["context"] = reqContext
		}
	}

	if event.User != nil {
		user := map[string]interface{}{}
		putString(user, "id", event.User.ID)
		putString(user, "email", event.User.Email)
		putString(user, "name", event.User.Name)
		putString(user, "first_name", event.User.FirstName)
		putString(user, "last_name", event.User.LastName)
		putString(user, "username", event.User.Username)
		putString(user, "phone", event.User.Phone)
		putString(user, "national_id", event.User.NationalID)
		putTime(user, "created_at", event.User.CreatedAt)
		putTime(user, "registered_at", event.User.RegisteredAt)
		putTime(user, "updated_at", event.User.UpdatedAt)

		if event.User.Address != nil {
			address := map[string]interface{}{}
			putString(address, "line1", event.User.Address.Line1)
			putString(address, "line2", event.User.Address.Line2)
			putString(address, "city", event.User.Address.City)
			putString(address, "region_code", event.User.Address.RegionCode)
			putString(address, "postal_code", event.User.Address.PostalCode)
			putString(address, "country_code", event.User.Address.CountryCode)
			if event.User.Address.Latitude != 0 {
				address["latitude"] = event.User.Address.Latitude
			}
			if event.User.Address.Longitude != 0 {
				address["longitude"] = event.User.Address.Longitude
			}
			if len(address) > 0 {
				user["address"] = address
			}
		}

		if len(user) > 0 {
			payload["user"] = user
		}
	}

	for key, value := range event.Attributes {
		if value != nil {
			payload[key] = value
		}
	}

	return payload, nil
}

// ContextFromRequest extracts the end user's IP and interesting headers from an
// inbound HTTP request, honouring X-Forwarded-For so you send the client IP
// rather than your proxy's.
//
// Only trust X-Forwarded-For when your edge sets it. If clients can reach your
// service directly they can forge it, so strip or overwrite the header at the
// proxy.
func ContextFromRequest(r *http.Request) *RequestContext {
	if r == nil {
		return nil
	}

	ctx := &RequestContext{Headers: make([][2]string, 0, len(interestingHeaders))}

	for _, name := range interestingHeaders {
		for _, value := range r.Header.Values(name) {
			if value != "" {
				ctx.Headers = append(ctx.Headers, [2]string{name, value})
			}
		}
	}

	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if first := strings.TrimSpace(strings.Split(forwarded, ",")[0]); first != "" {
			ctx.IP = first
		}
	}
	if ctx.IP == "" && r.RemoteAddr != "" {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			ctx.IP = host
		} else {
			ctx.IP = r.RemoteAddr
		}
	}

	return ctx
}

func putString(target map[string]interface{}, key, value string) {
	if value != "" {
		target[key] = value
	}
}

func putTime(target map[string]interface{}, key string, value *time.Time) {
	if value != nil && !value.IsZero() {
		target[key] = isoTime(*value)
	}
}

// isoTime renders RFC 3339 with milliseconds in UTC — what the Risk API expects.
func isoTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}
