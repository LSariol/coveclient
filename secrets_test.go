package coveclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// batchCove serves values like Cove 1.0: single reads and POST /v0/batch
// (all or nothing, missing keys listed in error.keys). forbidden keys are
// refused like a project token that can't read them. It counts requests.
type batchCove struct {
	values    map[string]string
	forbidden map[string]bool
	oldCove   bool // no batch endpoint, like Cove before 1.0
	requests  int
	batches   [][]string
}

func (f *batchCove) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.requests++
	switch {
	case r.URL.Path == "/v0/batch" && !f.oldCove:
		var body struct{ Keys []string }
		json.NewDecoder(r.Body).Decode(&body)
		f.batches = append(f.batches, body.Keys)

		for _, k := range body.Keys {
			if f.forbidden[k] {
				w.WriteHeader(http.StatusForbidden)
				io.WriteString(w, `{"success":false,"error":{"type":"forbidden_key","message":"test's token can't read one or more of the requested keys"}}`)
				return
			}
		}
		var missing []string
		var found []map[string]any
		for _, k := range body.Keys {
			if v, ok := f.values[k]; ok {
				found = append(found, map[string]any{"key": k, "value": v, "version": 1})
			} else {
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			keys, _ := json.Marshal(missing)
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"success":false,"error":{"type":"not_found","message":"no secret named %s","keys":%s}}`, strings.Join(missing, ", "), keys)
			return
		}
		io.WriteString(w, envelope(map[string]any{"secrets": found}))

	case strings.HasPrefix(r.URL.Path, "/v0/secrets/"):
		key := strings.TrimPrefix(r.URL.Path, "/v0/secrets/")
		value, ok := f.values[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"success":false,"error":{"type":"not_found","message":"secret not found"}}`)
			return
		}
		io.WriteString(w, envelope(map[string]any{"key": key, "value": value, "version": 1}))

	default: // like Go's ServeMux for an unknown route: plain text
		http.NotFound(w, r)
	}
}

func startFake(t *testing.T, f *batchCove) *Client {
	t.Helper()
	ts := httptest.NewServer(f)
	t.Cleanup(ts.Close)
	return New(ts.URL, "tok", "test")
}

func TestGetSecretsUsesOneRequest(t *testing.T) {
	f := &batchCove{values: map[string]string{"a": "1", "b": "2"}}
	got, err := startFake(t, f).GetSecrets("a", "b", "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["a"] != "1" || got["b"] != "2" {
		t.Fatalf("GetSecrets = %v", got)
	}
	if f.requests != 1 || !slices.Equal(f.batches[0], []string{"a", "b"}) {
		t.Fatalf("%d requests, batches %v; want one batch of a, b", f.requests, f.batches)
	}
}

func TestGetSecretsNamesEveryMissingKey(t *testing.T) {
	for _, old := range []bool{false, true} {
		f := &batchCove{values: map[string]string{"a": "1"}, oldCove: old}
		got, err := startFake(t, f).GetSecrets("a", "b", "c")
		if !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "b, c") {
			t.Fatalf("old Cove %v: err = %v, want ErrNotFound naming b and c", old, err)
		}
		if got != nil {
			t.Fatalf("old Cove %v: got values %v alongside an error", old, got)
		}
	}
}

func TestGetSecretsForbidden(t *testing.T) {
	f := &batchCove{values: map[string]string{"a": "1", "b": "2"}, forbidden: map[string]bool{"b": true}}
	_, err := startFake(t, f).GetSecrets("a", "b")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

func TestGetSecretsFallsBackOnAnOlderCove(t *testing.T) {
	f := &batchCove{values: map[string]string{"a": "1", "b": "2"}, oldCove: true}
	got, err := startFake(t, f).GetSecrets("a", "b")
	if err != nil || got["a"] != "1" || got["b"] != "2" {
		t.Fatalf("GetSecrets on an old Cove = %v, %v", got, err)
	}
	if f.requests != 3 { // the batch attempt, then one per key
		t.Errorf("%d requests, want 3", f.requests)
	}
}

func TestGetSecretsSplitsLargeRequests(t *testing.T) {
	f := &batchCove{values: map[string]string{}}
	var keys []string
	for i := 0; i < 250; i++ {
		k := fmt.Sprintf("k%d", i)
		f.values[k] = "v"
		keys = append(keys, k)
	}
	got, err := startFake(t, f).GetSecrets(keys...)
	if err != nil || len(got) != 250 {
		t.Fatalf("GetSecrets(250 keys) = %d values, %v", len(got), err)
	}
	if len(f.batches) != 3 || len(f.batches[0]) != 100 || len(f.batches[2]) != 50 {
		t.Fatalf("batch sizes = %d, want 100, 100, 50", len(f.batches))
	}
}

func TestGetSecretsChecksKeysFirst(t *testing.T) {
	f := &batchCove{}
	if _, err := startFake(t, f).GetSecrets("a", "bad key"); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("err = %v, want ErrInvalidKey", err)
	}
	if f.requests != 0 {
		t.Errorf("%d requests sent for an invalid key", f.requests)
	}
}

// A misbehaving server that leaves a key out mustn't produce a map with a
// silently missing value.
func TestGetSecretsRejectsAnIncompleteAnswer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, envelope(map[string]any{"secrets": []map[string]any{{"key": "a", "value": "1"}}}))
	}))
	defer ts.Close()

	if _, err := New(ts.URL, "tok", "test").GetSecrets("a", "b"); err == nil {
		t.Fatal("an answer without b was accepted")
	}
}
