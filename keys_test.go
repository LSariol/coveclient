package coveclient

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateKey(t *testing.T) {
	for _, key := range []string{"a", "MYAPP_API_KEY", "myapp.db-url", strings.Repeat("k", 256)} {
		if err := ValidateKey(key); err != nil {
			t.Errorf("ValidateKey(%q) = %v", key, err)
		}
	}
	for _, key := range []string{"", "has space", "a/b", "foo?x=1", "foo#bar", "../auth", "db:url", strings.Repeat("k", 257)} {
		if err := ValidateKey(key); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("ValidateKey(%q) = %v, want ErrInvalidKey", key, err)
		}
	}
}

// These keys used to change the URL: "?" started a query, "#" a fragment, and
// "../" walked to another endpoint, so the wrong secret (or an empty value)
// came back with no error. Now they're refused before any request is sent.
func TestKeysThatWouldChangeTheURLAreRefused(t *testing.T) {
	var requests int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
	}))
	defer ts.Close()
	c := New(ts.URL, "tok", "test")

	for _, key := range []string{"foo?x=1", "foo#bar", "../auth"} {
		if _, err := c.GetSecret(key); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("GetSecret(%q) = %v, want ErrInvalidKey", key, err)
		}
		if _, err := c.AddSecret(key, "v"); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("AddSecret(%q) = %v", key, err)
		}
		if err := c.UpdateSecret(key, "v"); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("UpdateSecret(%q) = %v", key, err)
		}
		if err := c.DeleteSecret(key); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("DeleteSecret(%q) = %v", key, err)
		}
	}
	if requests != 0 {
		t.Fatalf("%d requests were sent for invalid keys", requests)
	}
}

func TestGetSecretChecksTheReturnedKey(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(envelope(map[string]any{"key": "other.key", "value": "wrong", "version": 1})))
	}))
	defer ts.Close()

	value, err := New(ts.URL, "tok", "test").GetSecret("app.key")
	if err == nil || value != "" {
		t.Fatalf("GetSecret = %q, %v; want an error and no value", value, err)
	}
}
