package coveclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Dummy secret struct for testing
var testSecrets = []PublicSecretEntry{
	{Key: "db-password", DateAdded: "2025-07-01", LastModified: "2025-07-02"},
	{Key: "api-token", DateAdded: "2025-07-03", LastModified: "2025-07-04"},
}

// Dummy secret value response
var testSecretValue = struct {
	Value string `json:"value"`
}{
	Value: "s3cr3t!",
}

func TestGetSecret(t *testing.T) {
	// Create a fake server to simulate Cove
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer correct-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if r.URL.Path == "/secrets/db-password" {
			json.NewEncoder(w).Encode(testSecretValue)
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	client := New(server.URL, "correct-token")

	secret, err := client.GetSecret("db-password")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if secret != testSecretValue.Value {
		t.Errorf("expected %s, got %s", testSecretValue.Value, secret)
	}
}

func TestGetPublicKeyVault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer correct-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if r.URL.Path == "/secrets" {
			json.NewEncoder(w).Encode(testSecrets)
			return
		}

		http.NotFound(w, r)
	}))
	defer server.Close()

	client := New(server.URL, "correct-token")

	secrets, err := client.GetPublicKeyVault()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(secrets) != 2 {
		t.Errorf("expected 2 secrets, got %d", len(secrets))
	}

	if secrets[0].Key != "db-password" {
		t.Errorf("expected first secret to be 'db-password', got '%s'", secrets[0].Key)
	}
}
