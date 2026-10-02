package coveclient

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestClient(ts *httptest.Server, secret string) *Client {
	return New(ts.URL, secret)
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func envelope(data interface{}) string {
	b, _ := json.Marshal(map[string]interface{}{"success": true, "data": data})
	return string(b)
}

func TestNewClient(t *testing.T) {
	c := New("http://example", "tok")
	if c == nil {
		t.Fatalf("New returned nil")
	}
	if c.BaseURL != "http://example" || c.ClientSecret != "tok" {
		t.Fatalf("unexpected client fields: %+v", c)
	}
}

func TestGetSecret_Success(t *testing.T) {
	wantID := "alpha"
	wantAuth := "Bearer tok"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/v0/secrets/"+wantID {
			t.Fatalf("path = %s, want /v0/secrets/%s", r.URL.Path, wantID)
		}
		if got := r.Header.Get("Authorization"); got != wantAuth {
			t.Fatalf("Authorization = %q, want %q", got, wantAuth)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, envelope(map[string]interface{}{"key": "alpha", "value": "shh", "version": 1}))
	}))
	defer ts.Close()

	c := newTestClient(ts, "tok")
	got, err := c.GetSecret(wantID)
	if err != nil {
		t.Fatalf("GetSecret error: %v", err)
	}
	if got != "shh" {
		t.Fatalf("GetSecret = %q, want %q", got, "shh")
	}
}

func TestGetSecret_Non200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	c := newTestClient(ts, "tok")
	got, err := c.GetSecret("id")
	if err == nil || !strings.Contains(err.Error(), "Unexpected Status 500") {
		t.Fatalf("want status error, got: %v", err)
	}
	if got != "" {
		t.Fatalf("GetSecret value = %q, want empty", got)
	}
}

func TestGetSecret_BadJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"success":`) // malformed
	}))
	defer ts.Close()

	c := newTestClient(ts, "tok")
	_, err := c.GetSecret("id")
	if err == nil {
		t.Fatalf("expected JSON decode error")
	}
}

func TestGetSecret_RequestBuildError(t *testing.T) {
	c := &Client{BaseURL: "http://%", ClientSecret: "tok"}
	_, err := c.GetSecret("id")
	if err == nil {
		t.Fatalf("expected request build error")
	}
}

func TestGetAllSecrets_Success(t *testing.T) {
	t1 := time.Now().UTC().Truncate(time.Second)
	t2 := t1.Add(10 * time.Minute)

	entries := []map[string]interface{}{
		{
			"key":          "k1",
			"version":      1,
			"times_pulled": 3,
			"created_at":   t1.Format(time.RFC3339),
			"updated_at":   t2.Format(time.RFC3339),
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/v0/secrets" {
			t.Fatalf("path = %s, want /v0/secrets", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Fatalf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, envelope(map[string]interface{}{"secrets": entries}))
	}))
	defer ts.Close()

	c := newTestClient(ts, "tok")
	got, err := c.GetAllSecrets()
	if err != nil {
		t.Fatalf("GetAllSecrets error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Key != "k1" || got[0].Version != 1 || got[0].TimesPulled != 3 {
		t.Fatalf("unexpected entry: %+v", got[0])
	}
	if !got[0].DateAdded.Equal(t1) || !got[0].LastModified.Equal(t2) {
		t.Fatalf("unexpected times: DateAdded=%v LastModified=%v", got[0].DateAdded, got[0].LastModified)
	}
}

func TestGetAllSecrets_Non200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	c := newTestClient(ts, "tok")
	_, err := c.GetAllSecrets()
	if err == nil || !strings.Contains(err.Error(), "Unexpected Status 403") {
		t.Fatalf("want status error, got: %v", err)
	}
}

func TestGetAllSecrets_BadJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"bad":}`)
	}))
	defer ts.Close()

	c := newTestClient(ts, "tok")
	_, err := c.GetAllSecrets()
	if err == nil {
		t.Fatalf("expected JSON decode error")
	}
}

func TestAddSecret_Success(t *testing.T) {
	wantID := "alpha"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v0/secrets/"+wantID {
			t.Fatalf("path = %s, want /v0/secrets/%s", r.URL.Path, wantID)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Fatalf("Content-Type = %q", ct)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Fatalf("Authorization = %q", got)
		}
		var p secretPayload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if p.Value != "p@ss" {
			t.Fatalf("payload.Value = %q, want p@ss", p.Value)
		}
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, envelope(map[string]interface{}{"key": wantID, "action": "created", "message": "ok"}))
	}))
	defer ts.Close()

	c := newTestClient(ts, "tok")
	msg, err := c.AddSecret(wantID, "p@ss")
	if err != nil {
		t.Fatalf("AddSecret error: %v", err)
	}
	if msg != "ok" {
		t.Fatalf("message = %q, want ok", msg)
	}
}

func TestAddSecret_Non201(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	c := newTestClient(ts, "tok")
	_, err := c.AddSecret("id", "pw")
	if err == nil || !strings.Contains(err.Error(), "Unexpected Status 400") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAddSecret_BadJSONResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"success":`)
	}))
	defer ts.Close()

	c := newTestClient(ts, "tok")
	_, err := c.AddSecret("id", "pw")
	if err == nil {
		t.Fatalf("expected JSON decode error")
	}
}

func TestUpdateSecret_Success(t *testing.T) {
	wantID := "beta"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Fatalf("method = %s, want PATCH", r.Method)
		}
		if r.URL.Path != "/v0/secrets/"+wantID {
			t.Fatalf("path = %s, want /v0/secrets/%s", r.URL.Path, wantID)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Fatalf("Authorization = %q", got)
		}
		var p secretPayload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if p.Value != "new" {
			t.Fatalf("payload.Value = %q, want new", p.Value)
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, envelope(map[string]interface{}{"key": wantID, "action": "updated", "message": "updated"}))
	}))
	defer ts.Close()

	c := newTestClient(ts, "tok")
	if err := c.UpdateSecret(wantID, "new"); err != nil {
		t.Fatalf("UpdateSecret error: %v", err)
	}
}

func TestUpdateSecret_Non200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	c := newTestClient(ts, "tok")
	err := c.UpdateSecret("id", "pw")
	if err == nil || !strings.Contains(err.Error(), "Unexpected Status 400") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteSecret_Success(t *testing.T) {
	wantID := "gamma"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Fatalf("method = %s, want DELETE", r.Method)
		}
		if r.URL.Path != "/v0/secrets/"+wantID {
			t.Fatalf("path = %s, want /v0/secrets/%s", r.URL.Path, wantID)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Fatalf("Authorization = %q", got)
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, envelope(map[string]interface{}{"key": wantID, "action": "deleted", "message": "deleted"}))
	}))
	defer ts.Close()

	c := newTestClient(ts, "tok")
	if err := c.DeleteSecret(wantID); err != nil {
		t.Fatalf("DeleteSecret error: %v", err)
	}
}

func TestDeleteSecret_Non200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	c := newTestClient(ts, "tok")
	err := c.DeleteSecret("id")
	if err == nil || !strings.Contains(err.Error(), "Unexpected Status 404") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHealth_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/v0/health" {
			t.Fatalf("path = %s, want /v0/health", r.URL.Path)
		}
		io.WriteString(w, envelope(map[string]interface{}{"healthy": true, "time": time.Now().Format(time.RFC3339)}))
	}))
	defer ts.Close()

	c := newTestClient(ts, "tok")
	healthy, err := c.Health()
	if err != nil {
		t.Fatalf("Health error: %v", err)
	}
	if !healthy {
		t.Fatalf("Health = false, want true")
	}
}

func TestHealth_Non200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	c := newTestClient(ts, "tok")
	_, err := c.Health()
	if err == nil || !strings.Contains(err.Error(), "Unexpected Status 500") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuth_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/v0/auth" {
			t.Fatalf("path = %s, want /v0/auth", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Fatalf("Authorization = %q", got)
		}
		io.WriteString(w, envelope(map[string]interface{}{"authenticated": true, "time": time.Now().Format(time.RFC3339)}))
	}))
	defer ts.Close()

	c := newTestClient(ts, "tok")
	if err := c.Auth(); err != nil {
		t.Fatalf("Auth error: %v", err)
	}
}

func TestAuth_Non200(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	c := newTestClient(ts, "tok")
	err := c.Auth()
	if err == nil || !strings.Contains(err.Error(), "Unexpected Status 401") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHTTPDoError_Propagates(t *testing.T) {
	failing := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("boom")
	})}
	c := New("http://example", "tok", WithHTTPClient(failing))

	if _, err := c.GetSecret("id"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("GetSecret should propagate transport error, got %v", err)
	}
}
