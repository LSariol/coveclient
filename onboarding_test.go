package coveclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeCove serves the bootstrap and auth endpoints. While open is true the
// bootstrap endpoint hands out token; otherwise it refuses with 403.
type fakeCove struct {
	token      string
	open       atomic.Bool
	bootstraps atomic.Int32
}

func (f *fakeCove) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v0/bootstrap/lighthouse", func(w http.ResponseWriter, r *http.Request) {
		f.bootstraps.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if !f.open.Load() {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"success":false,"error":{"type":"bootstrap_locked","message":"the bootstrap endpoint is closed; open it with `+"`bootstrap open`"+` in the Cove CLI"}}`)
			return
		}
		io.WriteString(w, envelope(map[string]string{"secret": f.token}))
	})
	mux.HandleFunc("/v0/auth", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+f.token {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"success":false,"error":{"type":"invalid_token","message":"the provided token is invalid"}}`)
			return
		}
		io.WriteString(w, envelope(map[string]bool{"authenticated": true}))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestLoadOrBootstrapFetchesSavesAndReuses(t *testing.T) {
	cove := &fakeCove{token: "the-client-token-0123456789"}
	cove.open.Store(true)
	ts := cove.server(t)
	path := filepath.Join(t.TempDir(), "state", "cove-token")

	c := New(ts.URL, "", "lighthouse")
	token, err := c.LoadOrBootstrap(path)
	if err != nil {
		t.Fatal(err)
	}
	if token != cove.token || c.ClientSecret != cove.token {
		t.Fatalf("token = %q, ClientSecret = %q", token, c.ClientSecret)
	}

	saved, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(saved)) != cove.token {
		t.Fatalf("saved file = %q, %v", saved, err)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Errorf("token file permissions = %o, want 600", info.Mode().Perm())
		}
	}
	if leftovers, _ := filepath.Glob(path + ".tmp-*"); len(leftovers) != 0 {
		t.Errorf("temporary files left behind: %v", leftovers)
	}

	// A later start reads the file and doesn't call bootstrap again, even
	// with the endpoint closed.
	cove.open.Store(false)
	again := New(ts.URL, "", "lighthouse")
	if token, err := again.LoadOrBootstrap(path); err != nil || token != cove.token {
		t.Fatalf("second start = %q, %v", token, err)
	}
	if n := cove.bootstraps.Load(); n != 1 {
		t.Errorf("bootstrap endpoint called %d times, want 1", n)
	}
}

func TestLoadOrBootstrapExplainsAClosedEndpoint(t *testing.T) {
	cove := &fakeCove{token: "the-client-token-0123456789"}
	ts := cove.server(t)
	path := filepath.Join(t.TempDir(), "cove-token")

	_, err := New(ts.URL, "", "lighthouse").LoadOrBootstrap(path)
	if !errors.Is(err, ErrBootstrapClosed) {
		t.Fatalf("err = %v, want ErrBootstrapClosed", err)
	}
	if !strings.Contains(err.Error(), "bootstrap open") {
		t.Errorf("error doesn't say how to fix it: %v", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Error("a token file was written after a refusal")
	}
}

func TestLoadOrBootstrapRejectsAnEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cove-token")
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New("http://unused", "", "lighthouse").LoadOrBootstrap(path); err == nil {
		t.Fatal("an empty token file was accepted")
	}
}

func TestWaitForReady(t *testing.T) {
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v0/ready" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		io.WriteString(w, envelope(map[string]bool{"ready": true}))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := New(ts.URL, "", "test").WaitForReady(ctx); err != nil {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("checked %d times, want 3", n)
	}
}

func TestWaitForReadyFallsBackToHealthOnOlderCove(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v0/ready" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, envelope(map[string]bool{"healthy": true}))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := New(ts.URL, "", "test").WaitForReady(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestWaitForReadyGivesUp(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	err := New(ts.URL, "", "test").WaitForReady(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want a deadline error", err)
	}
}
