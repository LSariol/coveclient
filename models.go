package coveclient

import (
	"encoding/json"
	"time"
)

type PublicSecretEntry struct {
	Key          string    `json:"key"`
	Version      int       `json:"version"`
	TimesPulled  int       `json:"times_pulled"`
	DateAdded    time.Time `json:"created_at"`
	LastModified time.Time `json:"updated_at"`
}

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
	Type    string `json:"type"`
	Message string `json:"message"`
}
