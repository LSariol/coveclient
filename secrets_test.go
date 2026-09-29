package coveclient

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// secretServer serves GetSecret from values; any other key is a 404.
func secretServer(values map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/v0/secrets/")
		value, ok := values[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"success":false,"error":{"type":"not_found","message":"secret not found"}}`)
			return
		}
		io.WriteString(w, envelope(map[string]any{"key": key, "value": value, "version": 1}))
	}))
}

func TestGetSecrets(t *testing.T) {
	ts := secretServer(map[string]string{"a": "1", "b": "2"})
	defer ts.Close()

	got, err := New(ts.URL, "tok", "test").GetSecrets("a", "b", "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["a"] != "1" || got["b"] != "2" {
		t.Fatalf("GetSecrets = %v", got)
	}
}

func TestGetSecretsNamesEveryMissingKey(t *testing.T) {
	ts := secretServer(map[string]string{"a": "1"})
	defer ts.Close()

	got, err := New(ts.URL, "tok", "test").GetSecrets("a", "b", "c")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if !strings.Contains(err.Error(), "b, c") {
		t.Fatalf("err = %v, want it to name b and c", err)
	}
	if got != nil {
		t.Fatalf("got values %v alongside an error", got)
	}
}

func TestGetSecretsChecksKeysFirst(t *testing.T) {
	ts := secretServer(nil)
	defer ts.Close()

	if _, err := New(ts.URL, "tok", "test").GetSecrets("a", "bad key"); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("err = %v, want ErrInvalidKey", err)
	}
}
