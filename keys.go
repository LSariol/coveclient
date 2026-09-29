package coveclient

import (
	"errors"
	"fmt"
	"net/url"
)

// ErrInvalidKey is returned for a key Cove would reject, before any request is
// sent. Check for it with errors.Is.
var ErrInvalidKey = errors.New("invalid key")

// maxKeyLength is the longest key Cove accepts.
const maxKeyLength = 256

// ValidateKey reports whether key is a valid Cove secret key: 1 to 256
// characters, each a letter, digit, '.', '_' or '-'. Cove enforces the same
// rule. Use it to check your key names, e.g. in a unit test.
func ValidateKey(key string) error {
	if key == "" {
		return fmt.Errorf("coveClient: %w: the key is empty", ErrInvalidKey)
	}
	if len(key) > maxKeyLength {
		return fmt.Errorf("coveClient: %w: %q is longer than %d characters", ErrInvalidKey, key, maxKeyLength)
	}
	for _, c := range key {
		if !isValidKeyChar(c) {
			return fmt.Errorf("coveClient: %w: %q contains %q; only letters, digits, '.', '_' and '-' are allowed", ErrInvalidKey, key, c)
		}
	}
	return nil
}

func isValidKeyChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == '.'
}

// secretPath returns the API path for key, after checking it. Escaping is a
// second safeguard: a valid key never needs it.
func secretPath(key string) (string, error) {
	if err := ValidateKey(key); err != nil {
		return "", err
	}
	return "/v0/secrets/" + url.PathEscape(key), nil
}
