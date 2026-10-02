package coveclient

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// coveError answers like Cove does when a request fails.
func coveError(status int, errType, message string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, `{"success":false,"error":{"type":"`+errType+`","message":"`+message+`"}}`)
	}))
}

func TestErrorsIncludeCovesExplanation(t *testing.T) {
	ts := coveError(http.StatusNotFound, "not_found", "secret not found")
	defer ts.Close()

	_, err := New(ts.URL, "tok", "test").GetSecret("app.key")
	want := "coveClient: GetSecret: Unexpected Status 404: not_found: secret not found"
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v, want %q", err, want)
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err is %T, want *APIError", err)
	}
	if apiErr.Method != "GetSecret" || apiErr.StatusCode != 404 || apiErr.Type != "not_found" || apiErr.Message != "secret not found" {
		t.Fatalf("APIError = %+v", apiErr)
	}
}

func TestSentinelErrors(t *testing.T) {
	cases := []struct {
		status  int
		errType string
		want    error
	}{
		{http.StatusNotFound, "not_found", ErrNotFound},
		{http.StatusUnauthorized, "invalid_token", ErrUnauthorized},
		{http.StatusConflict, "already_exists", ErrAlreadyExists},
		{http.StatusBadRequest, "invalid_key", ErrInvalidKey},
		{http.StatusForbidden, "bootstrap_locked", ErrBootstrapClosed},
		{http.StatusForbidden, "forbidden_key", ErrForbidden},
	}
	all := []error{ErrNotFound, ErrUnauthorized, ErrAlreadyExists, ErrInvalidKey, ErrBootstrapClosed, ErrForbidden}

	for _, tc := range cases {
		err := &APIError{Method: "X", StatusCode: tc.status, Type: tc.errType}
		for _, sentinel := range all {
			if got := errors.Is(err, sentinel); got != (sentinel == tc.want) {
				t.Errorf("errors.Is(%d %s, %v) = %v", tc.status, tc.errType, sentinel, got)
			}
		}
	}
}

// A body that isn't Cove's JSON (e.g. an HTML page from a proxy) still gives
// the plain "Unexpected Status N" error.
func TestErrorWithoutCoveBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		io.WriteString(w, "<html>Bad Gateway</html>")
	}))
	defer ts.Close()

	err := New(ts.URL, "tok", "test").Auth()
	if err == nil || err.Error() != "coveClient: Auth: Unexpected Status 502" {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "Unexpected Status 502") {
		t.Fatal("lost the Unexpected Status text")
	}
}
