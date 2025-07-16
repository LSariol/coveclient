package coveclient

//Return type of getSecret
type SecretValue struct {
	Secret string `json:"secret"`
}

// Return type of GetPublicKeyVault
type PublicSecretEntry struct {
	Key          string `json:"key"`
	DateAdded    string `json:"dateAdded"`
	LastModified string `json:"lastModified"`
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
