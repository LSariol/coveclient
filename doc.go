// Package coveclient is the Go client for Cove, a self-hosted secret vault.
//
// Create a Client with New, get its token with LoadOrBootstrap (or pass one
// you already have), then read secrets:
//
//	c := coveclient.New("http://cove:2100", "", "myapp")
//	if _, err := c.LoadOrBootstrap("/data/cove.token"); err != nil {
//		log.Fatal(err)
//	}
//	secrets, err := c.GetSecrets("myapp.db-url", "myapp.api-key")
//
// Every method has a ...Context version that takes a context.Context. Failed
// requests return an *APIError, which matches ErrNotFound, ErrUnauthorized,
// ErrForbidden, ErrAlreadyExists, ErrInvalidKey or ErrBootstrapClosed with
// errors.Is.
//
// The token can be Cove's master token or a project token (`token create` in
// the Cove CLI), which only reaches the keys it was given; the client works
// the same with either.
//
// Requests time out after DefaultTimeout (15 seconds); change it with
// WithTimeout, or supply your own http.Client with WithHTTPClient.
package coveclient
