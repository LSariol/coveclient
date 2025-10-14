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

// helper to create a client pointing at a test server
func newTestClient(ts *httptest.Server, secret string) *Client {
    return New(ts.URL, secret)
}

// roundTripperFunc allows mocking http.DefaultClient.Do errors
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

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
        if r.URL.Path != "/secrets/"+wantID {
            t.Fatalf("path = %s, want /secrets/%s", r.URL.Path, wantID)
        }
        if got := r.Header.Get("Authorization"); got != wantAuth {
            t.Fatalf("Authorization = %q, want %q", got, wantAuth)
        }
        w.Header().Set("Content-Type", "application/json")
        io.WriteString(w, `{"secret":"shh"}`)
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
        io.WriteString(w, "oops")
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
        io.WriteString(w, `{"secret":`) // malformed
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

    entries := []PublicSecretEntry{
        {
            Key:          "k1",
            Version:      1,
            TimesPulled:  3,
            DateAdded:    t1,
            LastModified: t2,
        },
    }

    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet {
            t.Fatalf("method = %s, want GET", r.Method)
        }
        if r.URL.Path != "/secrets" {
            t.Fatalf("path = %s, want /secrets", r.URL.Path)
        }
        if got := r.Header.Get("Authorization"); got != "Bearer tok" {
            t.Fatalf("Authorization = %q, want %q", got, "Bearer tok")
        }
        w.Header().Set("Content-Type", "application/json")
        if err := json.NewEncoder(w).Encode(entries); err != nil {
            t.Fatalf("encode: %v", err)
        }
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
        t.Fatalf("unexpected times: %+v", got[0])
    }
}

func TestGetAllSecrets_Non200(t *testing.T) {
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusForbidden)
        io.WriteString(w, "forbidden")
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
    wantPayload := payload{SecretID: wantID, SecretValue: "p@ss"}

    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            t.Fatalf("method = %s, want POST", r.Method)
        }
        if r.URL.Path != "/secrets/"+wantID {
            t.Fatalf("path = %s, want /secrets/%s", r.URL.Path, wantID)
        }
        if ct := r.Header.Get("Content-Type"); ct != "application/json" {
            t.Fatalf("Content-Type = %q, want application/json", ct)
        }
        if got := r.Header.Get("Authorization"); got != "Bearer tok" {
            t.Fatalf("Authorization = %q, want %q", got, "Bearer tok")
        }
        var p payload
        if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
            t.Fatalf("decode payload: %v", err)
        }
        if p != wantPayload {
            t.Fatalf("payload = %+v, want %+v", p, wantPayload)
        }
        json.NewEncoder(w).Encode(response{Message: "ok"})
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

func TestAddSecret_Non200(t *testing.T) {
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusBadRequest)
        io.WriteString(w, "bad request")
    }))
    defer ts.Close()

    c := newTestClient(ts, "tok")
    _, err := c.AddSecret("id", "pw")
    if err == nil || !strings.Contains(err.Error(), "AddSecret: status 400 - bad request") {
        t.Fatalf("unexpected error: %v", err)
    }
}

func TestAddSecret_BadJSONResponse(t *testing.T) {
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        io.WriteString(w, `{"message":`)
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
    wantPayload := payload{SecretID: wantID, SecretValue: "new"}

    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPatch {
            t.Fatalf("method = %s, want PATCH", r.Method)
        }
        if r.URL.Path != "/secrets/"+wantID {
            t.Fatalf("path = %s, want /secrets/%s", r.URL.Path, wantID)
        }
        if got := r.Header.Get("Authorization"); got != "Bearer tok" {
            t.Fatalf("Authorization = %q, want %q", got, "Bearer tok")
        }
        var p payload
        if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
            t.Fatalf("decode payload: %v", err)
        }
        if p != wantPayload {
            t.Fatalf("payload = %+v, want %+v", p, wantPayload)
        }
        w.WriteHeader(http.StatusNoContent)
    }))
    defer ts.Close()

    c := newTestClient(ts, "tok")
    if err := c.UpdateSecret(wantID, "new"); err != nil {
        t.Fatalf("UpdateSecret error: %v", err)
    }
}

func TestUpdateSecret_Non204(t *testing.T) {
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusBadRequest)
        io.WriteString(w, "nope")
    }))
    defer ts.Close()

    c := newTestClient(ts, "tok")
    err := c.UpdateSecret("id", "pw")
    if err == nil || !strings.Contains(err.Error(), "UpdateSecret: status 400 - nope") {
        t.Fatalf("unexpected error: %v", err)
    }
}

func TestDeleteSecret_Success(t *testing.T) {
    wantID := "gamma"
    wantPayload := payload{SecretID: wantID, SecretValue: ""}

    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodDelete {
            t.Fatalf("method = %s, want DELETE", r.Method)
        }
        if r.URL.Path != "/secrets/"+wantID {
            t.Fatalf("path = %s, want /secrets/%s", r.URL.Path, wantID)
        }
        if got := r.Header.Get("Authorization"); got != "Bearer tok" {
            t.Fatalf("Authorization = %q, want %q", got, "Bearer tok")
        }
        if ct := r.Header.Get("Content-Type"); ct != "application/json" {
            t.Fatalf("Content-Type = %q, want application/json", ct)
        }
        var p payload
        if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
            t.Fatalf("decode payload: %v", err)
        }
        if p != wantPayload {
            t.Fatalf("payload = %+v, want %+v", p, wantPayload)
        }
        w.WriteHeader(http.StatusNoContent)
    }))
    defer ts.Close()

    c := newTestClient(ts, "tok")
    if err := c.DeleteSecret(wantID); err != nil {
        t.Fatalf("DeleteSecret error: %v", err)
    }
}

func TestDeleteSecret_Non204(t *testing.T) {
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusNotFound)
        io.WriteString(w, "not found")
    }))
    defer ts.Close()

    c := newTestClient(ts, "tok")
    err := c.DeleteSecret("id")
    if err == nil || !strings.Contains(err.Error(), "DeleteSecret: status 404 - not found") {
        t.Fatalf("unexpected error: %v", err)
    }
}

func TestBootstrap_Success(t *testing.T) {
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet {
            t.Fatalf("method = %s, want GET", r.Method)
        }
        if r.URL.Path != "/bootstrap/lighthouse" {
            t.Fatalf("path = %s, want /bootstrap/lighthouse", r.URL.Path)
        }
        io.WriteString(w, `{"secret":"beacon"}`)
    }))
    defer ts.Close()

    c := newTestClient(ts, "tok")
    got, err := c.Bootstrap()
    if err != nil {
        t.Fatalf("Bootstrap error: %v", err)
    }
    if got != "beacon" {
        t.Fatalf("Bootstrap = %q, want beacon", got)
    }
}

func TestBootstrap_Non200(t *testing.T) {
    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusInternalServerError)
        io.WriteString(w, "fail")
    }))
    defer ts.Close()

    c := newTestClient(ts, "tok")
    _, err := c.Bootstrap()
    if err == nil || !strings.Contains(err.Error(), "boostrap: bad status 500") {
        t.Fatalf("unexpected error: %v", err)
    }
}

func TestHTTPDoError_Propagates(t *testing.T) {
    // Arrange a transport that always fails
    oldTransport := http.DefaultTransport
    http.DefaultClient.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
        return nil, errors.New("boom")
    })
    defer func() { http.DefaultClient.Transport = oldTransport }()

    c := &Client{BaseURL: "http://example", ClientSecret: "tok"}

    if _, err := c.GetSecret("id"); err == nil || !strings.Contains(err.Error(), "boom") {
        t.Fatalf("GetSecret should propagate transport error, got %v", err)
    }
}
