package coveclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Errors you can check for with errors.Is. They match an *APIError with the
// corresponding status, e.g.
//
//	if errors.Is(err, coveclient.ErrNotFound) { ... }
var (
	ErrNotFound      = errors.New("not found")      // 404: no secret with that key
	ErrUnauthorized  = errors.New("unauthorized")   // 401: the token is missing or wrong
	ErrAlreadyExists = errors.New("already exists") // 409: AddSecret on an existing key

	// ErrForbidden means the client's project token doesn't cover the key:
	// it can't read it, or can't change it (403 forbidden_key). Grant access
	// in the Cove CLI with `token allow <key> <project>`.
	ErrForbidden = errors.New("forbidden")
)

// APIError is returned when Cove answers with a status other than the one that
// means success. Get it with errors.As to read the details:
//
//	var apiErr *coveclient.APIError
//	if errors.As(err, &apiErr) { log.Print(apiErr.StatusCode, apiErr.Type) }
type APIError struct {
	Method     string // the Client method that failed, e.g. "GetSecret"
	StatusCode int    // the HTTP status Cove answered with
	Type       string // Cove's error type, e.g. "not_found" (empty if Cove sent none)
	Message    string // Cove's explanation (empty if Cove sent none)

	// Keys lists the secret keys the error is about, when Cove says (e.g.
	// the missing keys of GetSecrets).
	Keys []string
}

// Error keeps the "Unexpected Status N" text of earlier versions, so code that
// looks for it still works, and adds Cove's explanation after it.
func (e *APIError) Error() string {
	s := fmt.Sprintf("coveClient: %s: Unexpected Status %d", e.Method, e.StatusCode)
	if e.Type != "" {
		s += ": " + e.Type
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	return s
}

// Is makes errors.Is(err, ErrNotFound) and the other sentinel errors work.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.StatusCode == http.StatusNotFound
	case ErrUnauthorized:
		return e.StatusCode == http.StatusUnauthorized
	case ErrAlreadyExists:
		return e.StatusCode == http.StatusConflict
	case ErrForbidden:
		return e.StatusCode == http.StatusForbidden && e.Type == "forbidden_key"
	case ErrInvalidKey:
		return e.StatusCode == http.StatusBadRequest && e.Type == "invalid_key"
	case ErrBootstrapClosed:
		return e.StatusCode == http.StatusForbidden && strings.HasPrefix(e.Type, "bootstrap_")
	}
	return false
}

// newAPIError builds an APIError from resp, reading Cove's error details when
// the body has them. A body that isn't Cove's JSON (e.g. from a proxy) is
// ignored.
func newAPIError(method string, resp *http.Response) *APIError {
	e := &APIError{Method: method, StatusCode: resp.StatusCode}

	var env apiResponse
	if json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&env) == nil && env.Error != nil {
		e.Type = env.Error.Type
		e.Message = env.Error.Message
		e.Keys = env.Error.Keys
	}
	return e
}
