package coveclient

import "time"

//Return type of getSecret
type SecretValue struct {
	Secret string `json:"secret"`
}

// Return type of GetPublicKeyVault
type PublicSecretEntry struct {
	Key          string    `json:"key"`
	Version      int       `json:"version"`
	TimesPulled  int       `json:"timespulled"`
	DateAdded    time.Time `json:"dateAdded"`
	LastModified time.Time `json:"lastModified"`
}

// Used for sending Create, Delete, Update requests
type payload struct {
	SecretID    string `json:"secretID"`
	SecretValue string `json:"secretValue"`
}

// Response from Create, Delete and Update requests
type response struct {
	Message string `json:"message"`
}
