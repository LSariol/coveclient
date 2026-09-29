package coveclient

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// GetSecrets returns the values of several secrets, keyed by name. It is
// GetSecretsContext with context.Background().
//
//	s, err := c.GetSecrets("myapp.db-url", "myapp.api-key")
//	if err != nil { log.Fatal(err) }
//	db := s["myapp.db-url"]
func (c *Client) GetSecrets(keys ...string) (map[string]string, error) {
	return c.GetSecretsContext(context.Background(), keys...)
}

// GetSecretsContext returns the values of several secrets, keyed by name.
//
// If any are missing, it returns an error naming all of them, not just the
// first, so one start-up tells you everything to add. That error matches
// ErrNotFound. Any other failure stops at the first one.
func (c *Client) GetSecretsContext(ctx context.Context, keys ...string) (map[string]string, error) {
	for _, key := range keys {
		if err := ValidateKey(key); err != nil {
			return nil, err
		}
	}

	values := make(map[string]string, len(keys))
	var missing []string
	for _, key := range keys {
		if _, done := values[key]; done {
			continue
		}
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
		return nil, fmt.Errorf("coveClient: GetSecrets: %w: %s", ErrNotFound, strings.Join(missing, ", "))
	}
	return values, nil
}
