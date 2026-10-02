package coveclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultTimeout is how long a request may take before it fails, unless
// changed with WithTimeout or WithHTTPClient.
const DefaultTimeout = 15 * time.Second

// Client talks to one Cove server. Create it with New. A Client is safe to use
// from several goroutines, as long as its fields aren't changed meanwhile.
type Client struct {
	BaseURL      string // e.g. "http://cove:2100"
	ClientSecret string // the token sent as "Authorization: Bearer ..."
	Platform     string // your app's name, sent as X-Cove-Source

	hc      *http.Client
	timeout time.Duration
}

// Option configures a Client. Pass options to New.
type Option func(*Client)

// WithTimeout sets how long a request may take before it fails (default
// DefaultTimeout).
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
}

// WithHTTPClient makes the Client send requests with hc, e.g. for a proxy or
// custom TLS settings. hc's own timeout and redirect settings apply.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.hc = hc }
}

// New returns a Client for the Cove server at baseURL. platformName identifies
// your app in Cove's event log (sent as X-Cove-Source) and is lowercased. If
// it's empty, the program's name is used.
func New(baseURL string, clientSecret string, platformName string, opts ...Option) *Client {
	c := &Client{
		BaseURL:      baseURL,
		ClientSecret: clientSecret,
		Platform:     strings.ToLower(platformName),
		timeout:      DefaultTimeout,
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.hc == nil {
		c.hc = newHTTPClient(c.timeout)
	}
	return c
}

// newHTTPClient returns an http.Client with a timeout that doesn't follow
// redirects: Cove never redirects on purpose, and following one would turn a
// POST, PATCH or DELETE into a GET.
func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

var defaultHTTPClient = newHTTPClient(DefaultTimeout)

// httpClient returns the client's http.Client. A Client built as a struct
// literal instead of with New gets the default one.
func (c *Client) httpClient() *http.Client {
	if c.hc != nil {
		return c.hc
	}
	return defaultHTTPClient
}

// url joins BaseURL and path. A trailing slash on BaseURL is ignored: it would
// make the path start with "//", which Cove answers with a redirect.
func (c *Client) url(path string) string {
	return strings.TrimRight(c.BaseURL, "/") + path
}

// source returns the name sent as X-Cove-Source. Cove refuses requests
// without one, so an empty Platform falls back to the program's name.
func (c *Client) source() string {
	if p := strings.TrimSpace(c.Platform); p != "" {
		return p
	}
	return programName()
}

// programName returns the running program's file name, lowercased and without
// ".exe", e.g. "lighthouse".
func programName() string {
	name := strings.ToLower(filepath.Base(os.Args[0]))
	name = strings.TrimSuffix(name, ".exe")
	if name == "" || name == "." {
		return "coveclient"
	}
	return name
}

// request describes one API call.
type request struct {
	name   string // the Client method, for error messages
	method string
	path   string // e.g. "/v0/secrets/KEY"
	body   any    // sent as JSON when not nil
	auth   bool   // send the Authorization header
	source bool   // send the X-Cove-Source header
	want   int    // the status code that means success
}

// do sends r and decodes the response's data into out (unless out is nil).
func (c *Client) do(ctx context.Context, r request, out any) error {
	var body io.Reader
	if r.body != nil {
		data, err := json.Marshal(r.body)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, r.method, c.url(r.path), body)
	if err != nil {
		return err
	}
	if r.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if r.auth {
		req.Header.Set("Authorization", "Bearer "+c.ClientSecret)
	}
	if r.source {
		req.Header.Set("X-Cove-Source", c.source())
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != r.want {
		return newAPIError(r.name, resp)
	}

	return decodeEnvelope(resp, out)
}

func decodeEnvelope(resp *http.Response, out interface{}) error {
	var env apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return err
	}
	if !env.Success {
		if env.Error != nil {
			return fmt.Errorf("coveClient: %s: %s", env.Error.Type, env.Error.Message)
		}
		return fmt.Errorf("coveClient: request failed (status %d)", resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(env.Data, out)
	}
	return nil
}

// GetSecret returns the value of the secret named key. It is
// GetSecretContext with context.Background().
func (c *Client) GetSecret(key string) (string, error) {
	return c.GetSecretContext(context.Background(), key)
}

// GetSecretContext returns the value of the secret named key. If there is no
// such secret, the error matches ErrNotFound.
func (c *Client) GetSecretContext(ctx context.Context, key string) (string, error) {
	path, err := secretPath(key)
	if err != nil {
		return "", err
	}

	var data struct {
		Key     string `json:"key"`
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	err = c.do(ctx, request{
		name: "GetSecret", method: http.MethodGet, path: path,
		auth: true, source: true, want: http.StatusOK,
	}, &data)
	if err != nil {
		return "", err
	}
	// Cove versions before 1.0.0 may leave the key out; a different key means
	// the request reached the wrong secret, so its value mustn't be used.
	if data.Key != "" && data.Key != key {
		return "", fmt.Errorf("coveClient: GetSecret: asked for %q but Cove returned %q", key, data.Key)
	}
	return data.Value, nil
}

// GetAllSecrets lists every secret's key and details, without values. It is
// GetAllSecretsContext with context.Background().
func (c *Client) GetAllSecrets() ([]PublicSecretEntry, error) {
	return c.GetAllSecretsContext(context.Background())
}

// GetAllSecretsContext lists every secret's key and details, without values.
func (c *Client) GetAllSecretsContext(ctx context.Context) ([]PublicSecretEntry, error) {
	var data struct {
		Secrets []PublicSecretEntry `json:"secrets"`
	}
	err := c.do(ctx, request{
		name: "GetAllSecrets", method: http.MethodGet, path: "/v0/secrets",
		auth: true, want: http.StatusOK,
	}, &data)
	if err != nil {
		return nil, err
	}
	return data.Secrets, nil
}

// AddSecret creates a secret and returns Cove's confirmation message. It is
// AddSecretContext with context.Background().
func (c *Client) AddSecret(key string, value string) (string, error) {
	return c.AddSecretContext(context.Background(), key, value)
}

// AddSecretContext creates a secret and returns Cove's confirmation message.
// If the key is taken, the error matches ErrAlreadyExists; use UpdateSecret to
// change an existing secret.
func (c *Client) AddSecretContext(ctx context.Context, key string, value string) (string, error) {
	path, err := secretPath(key)
	if err != nil {
		return "", err
	}

	var data struct {
		Key     string `json:"key"`
		Action  string `json:"action"`
		Message string `json:"message"`
	}
	err = c.do(ctx, request{
		name: "AddSecret", method: http.MethodPost, path: path,
		body: secretPayload{Value: value}, auth: true, source: true, want: http.StatusCreated,
	}, &data)
	if err != nil {
		return "", err
	}
	return data.Message, nil
}

// UpdateSecret changes an existing secret's value. It is UpdateSecretContext
// with context.Background().
func (c *Client) UpdateSecret(key string, value string) error {
	return c.UpdateSecretContext(context.Background(), key, value)
}

// UpdateSecretContext changes an existing secret's value. If there is no such
// secret, the error matches ErrNotFound.
func (c *Client) UpdateSecretContext(ctx context.Context, key string, value string) error {
	path, err := secretPath(key)
	if err != nil {
		return err
	}

	return c.do(ctx, request{
		name: "UpdateSecret", method: http.MethodPatch, path: path,
		body: secretPayload{Value: value}, auth: true, source: true, want: http.StatusOK,
	}, nil)
}

// DeleteSecret deletes a secret. It is DeleteSecretContext with
// context.Background().
func (c *Client) DeleteSecret(key string) error {
	return c.DeleteSecretContext(context.Background(), key)
}

// DeleteSecretContext deletes a secret. Cove keeps its history, so it can be
// restored with `restore` in the Cove CLI. If there is no such secret, the
// error matches ErrNotFound.
func (c *Client) DeleteSecretContext(ctx context.Context, key string) error {
	path, err := secretPath(key)
	if err != nil {
		return err
	}

	return c.do(ctx, request{
		name: "DeleteSecret", method: http.MethodDelete, path: path,
		auth: true, source: true, want: http.StatusOK,
	}, nil)
}

// Health reports whether Cove is running. It is HealthContext with
// context.Background().
func (c *Client) Health() (bool, error) {
	return c.HealthContext(context.Background())
}

// HealthContext reports whether Cove is running. It doesn't check Cove's
// database; WaitForReady does.
func (c *Client) HealthContext(ctx context.Context) (bool, error) {
	var data struct {
		Healthy bool   `json:"healthy"`
		Time    string `json:"time"`
	}
	err := c.do(ctx, request{
		name: "Health", method: http.MethodGet, path: "/v0/health",
		want: http.StatusOK,
	}, &data)
	if err != nil {
		return false, err
	}
	return data.Healthy, nil
}

// Auth checks that the client's token is accepted. It is AuthContext with
// context.Background().
func (c *Client) Auth() error {
	return c.AuthContext(context.Background())
}

// AuthContext checks that the client's token is accepted. If it isn't, the
// error matches ErrUnauthorized.
func (c *Client) AuthContext(ctx context.Context) error {
	return c.do(ctx, request{
		name: "Auth", method: http.MethodGet, path: "/v0/auth",
		auth: true, want: http.StatusOK,
	}, nil)
}
