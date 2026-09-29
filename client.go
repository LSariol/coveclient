package coveclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultTimeout is how long a request may take before it fails, unless
// changed with WithTimeout or WithHTTPClient.
const DefaultTimeout = 15 * time.Second

type Client struct {
	BaseURL      string
	ClientSecret string
	Platform     string

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
// your app in Cove's event log (sent as X-Cove-Source) and is lowercased.
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
		req.Header.Set("X-Cove-Source", c.Platform)
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

func (c *Client) GetSecret(id string) (string, error) {
	path, err := secretPath(id)
	if err != nil {
		return "", err
	}

	var data struct {
		Key     string `json:"key"`
		Value   string `json:"value"`
		Version int    `json:"version"`
	}
	err = c.do(context.Background(), request{
		name: "GetSecret", method: http.MethodGet, path: path,
		auth: true, source: true, want: http.StatusOK,
	}, &data)
	if err != nil {
		return "", err
	}
	// Cove versions before 1.0.0 may leave the key out; a different key means
	// the request reached the wrong secret, so its value mustn't be used.
	if data.Key != "" && data.Key != id {
		return "", fmt.Errorf("coveClient: GetSecret: asked for %q but Cove returned %q", id, data.Key)
	}
	return data.Value, nil
}

func (c *Client) GetAllSecrets() ([]PublicSecretEntry, error) {
	var data struct {
		Secrets []PublicSecretEntry `json:"secrets"`
	}
	err := c.do(context.Background(), request{
		name: "GetAllSecrets", method: http.MethodGet, path: "/v0/secrets",
		auth: true, want: http.StatusOK,
	}, &data)
	if err != nil {
		return nil, err
	}
	return data.Secrets, nil
}

func (c *Client) AddSecret(id string, value string) (string, error) {
	path, err := secretPath(id)
	if err != nil {
		return "", err
	}

	var data struct {
		Key     string `json:"key"`
		Action  string `json:"action"`
		Message string `json:"message"`
	}
	err = c.do(context.Background(), request{
		name: "AddSecret", method: http.MethodPost, path: path,
		body: secretPayload{Value: value}, auth: true, source: true, want: http.StatusCreated,
	}, &data)
	if err != nil {
		return "", err
	}
	return data.Message, nil
}

func (c *Client) UpdateSecret(id string, value string) error {
	path, err := secretPath(id)
	if err != nil {
		return err
	}

	return c.do(context.Background(), request{
		name: "UpdateSecret", method: http.MethodPatch, path: path,
		body: secretPayload{Value: value}, auth: true, source: true, want: http.StatusOK,
	}, nil)
}

func (c *Client) DeleteSecret(id string) error {
	path, err := secretPath(id)
	if err != nil {
		return err
	}

	return c.do(context.Background(), request{
		name: "DeleteSecret", method: http.MethodDelete, path: path,
		auth: true, source: true, want: http.StatusOK,
	}, nil)
}

func (c *Client) Bootstrap() (string, error) {
	var data SecretValue
	err := c.do(context.Background(), request{
		name: "Bootstrap", method: http.MethodGet, path: "/v0/bootstrap/lighthouse",
		want: http.StatusOK,
	}, &data)
	if err != nil {
		return "", err
	}
	return data.Secret, nil
}

func (c *Client) Health() (bool, error) {
	var data struct {
		Healthy bool   `json:"healthy"`
		Time    string `json:"time"`
	}
	err := c.do(context.Background(), request{
		name: "Health", method: http.MethodGet, path: "/v0/health",
		want: http.StatusOK,
	}, &data)
	if err != nil {
		return false, err
	}
	return data.Healthy, nil
}

func (c *Client) Auth() error {
	return c.do(context.Background(), request{
		name: "Auth", method: http.MethodGet, path: "/v0/auth",
		auth: true, want: http.StatusOK,
	}, nil)
}
