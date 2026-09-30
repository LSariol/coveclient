package coveclient

import (
	"encoding/json"
	"time"
)

// PublicSecretEntry describes a secret without its value, as listed by
// GetAllSecrets.
type PublicSecretEntry struct {
	Key          string    `json:"key"`
	Version      int       `json:"version"`      // goes up by one on each update
	TimesPulled  int       `json:"times_pulled"` // how many times it has been read
	DateAdded    time.Time `json:"created_at"`
	LastModified time.Time `json:"updated_at"`
}

// SecretValue is the token returned by Cove's bootstrap endpoint.
type SecretValue struct {
	Secret string `json:"secret"`
}

type secretPayload struct {
	Value string `json:"value"`
}

type apiResponse struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   *apiError       `json:"error"`
}

type apiError struct {
	Type    string   `json:"type"`
	Message string   `json:"message"`
	Keys    []string `json:"keys"`
}
