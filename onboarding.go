package coveclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrBootstrapClosed is returned by LoadOrBootstrap when Cove refused to hand
// out the token: its bootstrap endpoint is closed, the window expired, or this
// address isn't allowed. Run `bootstrap open` in the Cove CLI, then retry.
var ErrBootstrapClosed = errors.New("coveClient: Cove's bootstrap endpoint refused the request")

// LoadOrBootstrap gets this client's token and sets it as c.ClientSecret.
//
// If the file at path exists, the token is read from it and no request is
// made. Otherwise the token is fetched from Cove's bootstrap endpoint, saved to
// path right away (readable only by its owner, and written so a crash can't
// leave a partial file), and checked with Auth. Call it on every start: the
// first start onboards the client, later starts just read the file.
//
// If Cove refuses, the error wraps ErrBootstrapClosed and says why.
func (c *Client) LoadOrBootstrap(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		token := strings.TrimSpace(string(data))
		if token == "" {
			return "", fmt.Errorf("coveClient: token file %s is empty; delete it to bootstrap again", path)
		}
		c.ClientSecret = token
		return token, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("coveClient: read token file: %w", err)
	}

	token, err := c.fetchBootstrapToken()
	if err != nil {
		return "", err
	}

	if err := writeTokenFile(path, token); err != nil {
		return "", err
	}
	c.ClientSecret = token

	if err := c.Auth(); err != nil {
		return "", fmt.Errorf("coveClient: the bootstrapped token was saved to %s but didn't authenticate: %w", path, err)
	}
	return token, nil
}

// fetchBootstrapToken calls the bootstrap endpoint and explains a refusal.
func (c *Client) fetchBootstrapToken() (string, error) {
	resp, err := http.Get(fmt.Sprintf("%s/v0/bootstrap/lighthouse", c.BaseURL))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var env apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return "", fmt.Errorf("coveClient: Bootstrap: unexpected response (status %d): %w", resp.StatusCode, err)
	}

	if resp.StatusCode == http.StatusForbidden {
		reason := "the endpoint is closed"
		if env.Error != nil {
			reason = env.Error.Message
		}
		return "", fmt.Errorf("%w: %s", ErrBootstrapClosed, reason)
	}
	if resp.StatusCode != http.StatusOK || !env.Success {
		if env.Error != nil {
			return "", fmt.Errorf("coveClient: Bootstrap: %s: %s", env.Error.Type, env.Error.Message)
		}
		return "", fmt.Errorf("coveClient: Bootstrap: Unexpected Status %d", resp.StatusCode)
	}

	var data SecretValue
	if err := json.Unmarshal(env.Data, &data); err != nil {
		return "", err
	}
	if data.Secret == "" {
		return "", errors.New("coveClient: Bootstrap: Cove returned an empty token")
	}
	return data.Secret, nil
}

// writeTokenFile saves token to path, readable only by its owner. It writes a
// temporary file and renames it into place, so the file is either absent or
// complete, never half-written.
func writeTokenFile(path string, token string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("coveClient: create token directory: %w", err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("coveClient: save token: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op once renamed

	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		tmp.Close()
		return fmt.Errorf("coveClient: save token: %w", err)
	}
	if _, err := tmp.WriteString(token + "\n"); err != nil {
		tmp.Close()
		return fmt.Errorf("coveClient: save token: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("coveClient: save token: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("coveClient: save token: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("coveClient: save token: %w", err)
	}
	return nil
}

// WaitForReady waits until Cove is up and can serve secrets, checking with a
// growing delay (up to 5 seconds) until ctx is done. It uses /v0/ready, which
// also checks Cove's database, and falls back to /v0/health for Cove versions
// that don't have it.
//
//	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
//	defer cancel()
//	if err := c.WaitForReady(ctx); err != nil { ... }
func (c *Client) WaitForReady(ctx context.Context) error {
	delay := 250 * time.Millisecond
	for {
		if c.isReady(ctx) {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("coveClient: Cove at %s wasn't ready: %w", c.BaseURL, ctx.Err())
		case <-time.After(delay):
		}
		delay = min(delay*2, 5*time.Second)
	}
}

func (c *Client) isReady(ctx context.Context) bool {
	status := c.checkStatus(ctx, "/v0/ready")
	if status == http.StatusNotFound {
		status = c.checkStatus(ctx, "/v0/health") // Cove before v1.0.0
	}
	return status == http.StatusOK
}

// checkStatus returns the HTTP status of GET path, or 0 if the request failed.
func (c *Client) checkStatus(ctx context.Context, path string) int {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return 0
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}
