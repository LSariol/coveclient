package coveclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// GetSecrets returns the values of several secrets, keyed by name. It is
// GetSecretsContext with context.Background().
//
//	s, err := c.GetSecrets("MYAPP_DATABASE_URL", "MYAPP_TMDB_API_KEY")
//	if err != nil { log.Fatal(err) }
//	db := s["MYAPP_DATABASE_URL"]
func (c *Client) GetSecrets(keys ...string) (map[string]string, error) {
	return c.GetSecretsContext(context.Background(), keys...)
}

// GetSecretsContext returns the values of several secrets, keyed by name, in
// one request (Cove's POST /v0/batch; up to 100 keys per request, more are
// split). On a Cove without that endpoint it asks for each key in turn.
//
// If any are missing, it returns an error naming all of them, not just the
// first, so one start-up tells you everything to add. That error matches
// ErrNotFound. If the token can't read one of them, the error matches
// ErrForbidden (Cove doesn't say which one; its server log does). Every key
// is checked with ValidateKey before any request is sent.
func (c *Client) GetSecretsContext(ctx context.Context, keys ...string) (map[string]string, error) {
	for _, key := range keys {
		if err := ValidateKey(key); err != nil {
			return nil, err
		}
	}
	keys = dedupe(keys)

	values := make(map[string]string, len(keys))
	var missing []string
	for start := 0; start < len(keys); start += maxBatchKeys {
		chunk := keys[start:min(start+maxBatchKeys, len(keys))]

		got, err := c.batch(ctx, chunk)
		if errors.Is(err, errNoBatch) {
			return c.getEach(ctx, keys)
		}
		var m *missingKeysError
		if errors.As(err, &m) {
			missing = append(missing, m.keys...)
			continue
		}
		if err != nil {
			return nil, err
		}
		for k, v := range got {
			values[k] = v
		}
	}

	if len(missing) > 0 {
		return nil, missingError(missing)
	}
	return values, nil
}

// maxBatchKeys is the most keys Cove accepts in one batch request.
const maxBatchKeys = 100

// errNoBatch means the Cove server predates POST /v0/batch.
var errNoBatch = errors.New("coveClient: this Cove has no batch endpoint")

type missingKeysError struct{ keys []string }

func (e *missingKeysError) Error() string { return "missing: " + strings.Join(e.keys, ", ") }

func missingError(keys []string) error {
	return fmt.Errorf("coveClient: GetSecrets: %w: %s", ErrNotFound, strings.Join(keys, ", "))
}

// batch reads keys (at most maxBatchKeys, no duplicates) in one request.
func (c *Client) batch(ctx context.Context, keys []string) (map[string]string, error) {
	var data struct {
		Secrets []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"secrets"`
	}
	err := c.do(ctx, request{
		name: "GetSecrets", method: http.MethodPost, path: "/v0/batch",
		body: struct {
			Keys []string `json:"keys"`
		}{keys},
		auth: true, source: true, want: http.StatusOK,
	}, &data)

	var apiErr *APIError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.Type == "" && (apiErr.StatusCode == http.StatusNotFound || apiErr.StatusCode == http.StatusMethodNotAllowed):
			return nil, errNoBatch // not Cove's JSON: the route doesn't exist
		case apiErr.StatusCode == http.StatusNotFound && len(apiErr.Keys) > 0:
			return nil, &missingKeysError{keys: apiErr.Keys}
		}
	}
	if err != nil {
		return nil, err
	}

	// Every key asked for must come back, and nothing else.
	values := make(map[string]string, len(data.Secrets))
	for _, s := range data.Secrets {
		values[s.Key] = s.Value
	}
	if len(values) != len(keys) {
		return nil, fmt.Errorf("coveClient: GetSecrets: asked for %d secrets but Cove returned %d", len(keys), len(values))
	}
	for _, k := range keys {
		if _, ok := values[k]; !ok {
			return nil, fmt.Errorf("coveClient: GetSecrets: Cove didn't return %q", k)
		}
	}
	return values, nil
}

// getEach reads keys one request at a time, for a Cove without the batch
// endpoint.
func (c *Client) getEach(ctx context.Context, keys []string) (map[string]string, error) {
	values := make(map[string]string, len(keys))
	var missing []string
	for _, key := range keys {
		value, err := c.GetSecretContext(ctx, key)
		if errors.Is(err, ErrNotFound) {
			missing = append(missing, key)
			continue
		}
		if err != nil {
			return nil, err
		}
		values[key] = value
	}
	if len(missing) > 0 {
		return nil, missingError(missing)
	}
	return values, nil
}

func dedupe(keys []string) []string {
	seen := make(map[string]bool, len(keys))
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}
