package coveclient

type SecretValue struct {
	Secret string `json:"secret"`
}

// Return type of GetPublicKeyVault
type PublicSecretEntry struct {
	Key          string `json:"key"`
	DateAdded    string `json:"dateAdded"`
	LastModified string `json:"lastModified"`
}
