package coveclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Dummy data and helpers
var testSecret = "supersecret"
var testMessage = "Operation successful"
var testID = "api-key"
var testEntries = []PublicSecretEntry{
	{Key: "api-key", DateAdded: "2025-07-01", LastModified: "2025-07-02"},
	{Key: "db-token", DateAdded: "2025-07-03", LastModified: "2025-07-04"},
}

func newTestServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-secret" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/secrets/"):
			json.NewEncoder(w).Encode(SecretValue{Secret: testSecret})
		case r.Method == http.MethodGet && r.URL.Path == "/secrets":
			json.NewEncoder(w).Encode(testEntries)
		case r.Method == http.MethodPost && r.URL.Path == "/secrets":
			json.NewEncoder(w).Encode(response{Message: testMessage})
		case r.Method == http.MethodPatch && r.URL.Path == "/secrets":
			json.NewEncoder(w).Encode(response{Message: testMessage})
		case r.Method == http.MethodDelete && r.URL.Path == "/secrets":
			json.NewEncoder(w).Encode(response{Message: testMessage})
		default:
			t.Errorf("Unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "Not found", http.StatusNotFound)
		}
	}))
}

func TestGetSecret(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := New(ts.URL, "test-secret")
	secret, err := client.GetSecret("api-key")
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}
	if secret != testSecret {
		t.Errorf("expected %q, got %q", testSecret, secret)
	}
}

func TestGetAllSecrets(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := New(ts.URL, "test-secret")
	secrets, err := client.GetAllSecrets()
	if err != nil {
		t.Fatalf("GetAllSecrets failed: %v", err)
	}
	if len(secrets) != len(testEntries) {
		t.Errorf("expected %d entries, got %d", len(testEntries), len(secrets))
	}
}

func TestAddSecret(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := New(ts.URL, "test-secret")
	msg, err := client.AddSecret("new-key", "value123")
	if err != nil {
		t.Fatalf("AddSecret failed: %v", err)
	}
	if msg != testMessage {
		t.Errorf("expected message %q, got %q", testMessage, msg)
	}
}

func TestUpdateSecret(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := New(ts.URL, "test-secret")
	msg, err := client.UpdateSecret("api-key", "updated123")
	if err != nil {
		t.Fatalf("UpdateSecret failed: %v", err)
	}
	if msg != testMessage {
		t.Errorf("expected message %q, got %q", testMessage, msg)
	}
}

func TestDeleteSecret(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := New(ts.URL, "test-secret")
	msg, err := client.DeleteSecret("api-key")
	if err != nil {
		t.Fatalf("DeleteSecret failed: %v", err)
	}
	if msg != testMessage {
		t.Errorf("expected message %q, got %q", testMessage, msg)
	}
}
