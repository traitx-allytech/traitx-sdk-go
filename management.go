package traitx

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Management wraps the portal policy and list APIs (SPEC.md §2).
//
// These calls authenticate with a bearer JWT obtained by a human operator
// logging in, not with the private key, and they are application-scoped. Unlike
// Evaluate, they return errors: an admin script should fail loudly, not
// silently no-op.
//
// Typical uses: assert at boot that the policies you rely on are enabled, and
// push a confirmed-fraud device or IP onto a blocklist after a chargeback.
type Management struct {
	cfg       Config
	transport *transport
	token     string
}

// PolicyTrigger is one condition in a policy.
type PolicyTrigger struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value,omitempty"`
	ListID   string      `json:"list_id,omitempty"`
}

// Policy mirrors models.Policy on the API side.
type Policy struct {
	ID            string          `json:"id"`
	TenantID      string          `json:"tenant_id"`
	ApplicationID string          `json:"application_id"`
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	EventGroup    string          `json:"event_group"`
	Order         int             `json:"order"`
	Enabled       bool            `json:"enabled"`
	PassThrough   bool            `json:"pass_through"`
	InlineAction  string          `json:"inline_action,omitempty"`
	Triggers      []PolicyTrigger `json:"triggers"`
	Deleted       bool            `json:"deleted"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// List mirrors models.List on the API side.
type List struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	ApplicationID string    `json:"application_id"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	ListType      string    `json:"list_type"`
	Color         string    `json:"color"`
	EntryCount    int       `json:"entry_count"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ListEntry is one value in a list.
type ListEntry struct {
	ID        string     `json:"id"`
	ListID    string     `json:"list_id"`
	Value     string     `json:"value"`
	Comment   string     `json:"comment"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Archived  bool       `json:"archived"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// NewEntry describes a value to add to a list.
type NewEntry struct {
	Value     string
	Comment   string
	ExpiresAt *time.Time
}

// PolicyAudit summarises which policies are live, shadowed or disabled.
type PolicyAudit struct {
	Total    int
	Live     []string
	Shadow   []string
	Disabled []string
}

// WithToken supplies the portal JWT.
//
// Obtain it however your operations tooling prefers — POST /api/v1/user/login
// plus OTP verification returns one. The SDK does not perform the login flow
// because it involves a second factor.
func (m *Management) WithToken(jwt string) *Management {
	m.token = strings.TrimPrefix(strings.TrimSpace(jwt), "Bearer ")
	return m
}

// -- policies ---------------------------------------------------------------

// ListPolicies returns the policies for an application. Pass "" to use the
// client's configured ApplicationID.
func (m *Management) ListPolicies(ctx context.Context, applicationID string) ([]Policy, error) {
	var wrapper struct {
		Policies []Policy `json:"policies"`
	}
	err := m.call(ctx, "GET", "/api/v1/policies",
		map[string]string{"application_id": m.appID(applicationID)}, nil, &wrapper)
	return wrapper.Policies, err
}

// GetPolicy reads one policy.
func (m *Management) GetPolicy(ctx context.Context, id string) (Policy, error) {
	var policy Policy
	err := m.call(ctx, "GET", "/api/v1/policies/"+url.PathEscape(id), nil, nil, &policy)
	return policy, err
}

// EnablePolicy turns a policy on.
func (m *Management) EnablePolicy(ctx context.Context, id string) error {
	return m.call(ctx, "PATCH", "/api/v1/policies/"+url.PathEscape(id)+"/enable", nil, nil, nil)
}

// DisablePolicy turns a policy off.
func (m *Management) DisablePolicy(ctx context.Context, id string) error {
	return m.call(ctx, "PATCH", "/api/v1/policies/"+url.PathEscape(id)+"/disable", nil, nil, nil)
}

// EnableShadowMode puts a policy into shadow mode: it evaluates and logs but
// does not enforce.
func (m *Management) EnableShadowMode(ctx context.Context, id string) error {
	return m.call(ctx, "PATCH",
		"/api/v1/policies/"+url.PathEscape(id)+"/pass-through/enable", nil, nil, nil)
}

// DisableShadowMode promotes a policy out of shadow mode so its action is enforced.
func (m *Management) DisableShadowMode(ctx context.Context, id string) error {
	return m.call(ctx, "PATCH",
		"/api/v1/policies/"+url.PathEscape(id)+"/pass-through/disable", nil, nil, nil)
}

// AuditPolicies reports which policies are live, shadowed or disabled. Run it at
// boot and log the result rather than assuming the control plane matches your code.
func (m *Management) AuditPolicies(ctx context.Context, applicationID string) (PolicyAudit, error) {
	policies, err := m.ListPolicies(ctx, applicationID)
	if err != nil {
		return PolicyAudit{}, err
	}
	audit := PolicyAudit{Total: len(policies)}
	for _, policy := range policies {
		switch {
		case !policy.Enabled:
			audit.Disabled = append(audit.Disabled, policy.Name)
		case policy.PassThrough:
			audit.Shadow = append(audit.Shadow, policy.Name)
		default:
			audit.Live = append(audit.Live, policy.Name)
		}
	}
	return audit, nil
}

// -- lists ------------------------------------------------------------------

// ListLists returns the lists for an application.
func (m *Management) ListLists(ctx context.Context, applicationID string) ([]List, error) {
	var wrapper struct {
		Lists []List `json:"lists"`
	}
	err := m.call(ctx, "GET", "/api/v1/lists",
		map[string]string{"application_id": m.appID(applicationID)}, nil, &wrapper)
	return wrapper.Lists, err
}

// ListEntries returns a page of entries from a list.
func (m *Management) ListEntries(
	ctx context.Context, listID string, limit, offset int,
) ([]ListEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	var wrapper struct {
		Entries []ListEntry `json:"entries"`
	}
	err := m.call(ctx, "GET", "/api/v1/lists/"+url.PathEscape(listID)+"/entries",
		map[string]string{"limit": strconv.Itoa(limit), "offset": strconv.Itoa(offset)},
		nil, &wrapper)
	return wrapper.Entries, err
}

// AddEntry adds one value — a device id, IP, email domain, BIN — to a list.
func (m *Management) AddEntry(ctx context.Context, listID string, entry NewEntry) (ListEntry, error) {
	if strings.TrimSpace(entry.Value) == "" {
		return ListEntry{}, fmt.Errorf("traitx: entry.Value is required")
	}
	body := map[string]interface{}{"value": entry.Value}
	if entry.Comment != "" {
		body["comment"] = entry.Comment
	}
	if entry.ExpiresAt != nil {
		body["expires_at"] = isoTime(*entry.ExpiresAt)
	}
	var created ListEntry
	err := m.call(ctx, "POST", "/api/v1/lists/"+url.PathEscape(listID)+"/entries",
		nil, body, &created)
	return created, err
}

// AddEntries bulk-adds values. The API accepts at most 1000 per call.
func (m *Management) AddEntries(ctx context.Context, listID string, entries []NewEntry) error {
	if len(entries) == 0 {
		return fmt.Errorf("traitx: at least one entry is required")
	}
	if len(entries) > 1000 {
		return fmt.Errorf("traitx: the API accepts at most 1000 entries per call, got %d",
			len(entries))
	}
	prepared := make([]map[string]interface{}, 0, len(entries))
	for _, entry := range entries {
		item := map[string]interface{}{"value": entry.Value}
		if entry.Comment != "" {
			item["comment"] = entry.Comment
		}
		if entry.ExpiresAt != nil {
			item["expires_at"] = isoTime(*entry.ExpiresAt)
		}
		prepared = append(prepared, item)
	}
	return m.call(ctx, "POST", "/api/v1/lists/"+url.PathEscape(listID)+"/entries/bulk",
		nil, map[string]interface{}{"entries": prepared}, nil)
}

// ArchiveEntry archives one entry, keeping it for audit while removing it from
// matching.
func (m *Management) ArchiveEntry(ctx context.Context, listID, entryID string) error {
	return m.call(ctx, "PATCH",
		"/api/v1/lists/"+url.PathEscape(listID)+"/entries/"+url.PathEscape(entryID)+"/archive",
		nil, nil, nil)
}

// DeleteEntry removes one entry outright.
func (m *Management) DeleteEntry(ctx context.Context, listID, entryID string) error {
	return m.call(ctx, "DELETE",
		"/api/v1/lists/"+url.PathEscape(listID)+"/entries/"+url.PathEscape(entryID),
		nil, nil, nil)
}

// -- internals --------------------------------------------------------------

func (m *Management) appID(override string) string {
	if override != "" {
		return override
	}
	return m.cfg.ApplicationID
}

func (m *Management) call(
	ctx context.Context,
	method, path string,
	query map[string]string,
	body interface{},
	out interface{},
) error {
	if m.token == "" {
		return fmt.Errorf("traitx: management calls need a portal JWT — " +
			"client.Management.WithToken(jwt); the private API key does not authorise the " +
			"policy and list endpoints")
	}

	outcome := m.transport.send(ctx, requestSpec{
		method:     method,
		path:       path,
		query:      query,
		body:       body,
		omitAPIKey: true,
		headers:    map[string]string{"Authorization": "Bearer " + m.token},
	})

	if outcome.TransportError != "" {
		return fmt.Errorf("traitx: %s %s: %s", method, path, outcome.TransportError)
	}
	if outcome.StatusCode >= 400 {
		detail := "no detail"
		if s := asString(outcome.Body["error"]); s != "" {
			detail = s
		} else if s := asString(outcome.Body["message"]); s != "" {
			detail = s
		}
		return &APIError{
			StatusCode: outcome.StatusCode,
			Body:       outcome.Body,
			Message: fmt.Sprintf("%s %s failed: HTTP %d — %s",
				method, path, outcome.StatusCode, detail),
		}
	}
	if out == nil || outcome.Body == nil {
		return nil
	}

	// Re-marshal the generic map into the caller's struct. The extra hop keeps
	// the transport a single, tolerant JSON decoder for every call.
	raw, err := json.Marshal(outcome.Body)
	if err != nil {
		return fmt.Errorf("traitx: could not re-encode response: %w", err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("traitx: could not decode %s %s response: %w", method, path, err)
	}
	return nil
}
