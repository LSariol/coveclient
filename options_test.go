package coveclient

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDefaultTimeout(t *testing.T) {
	c := New("http://example", "tok", "test")
	if c.httpClient().Timeout != DefaultTimeout {
		t.Fatalf("timeout = %v, want %v", c.httpClient().Timeout, DefaultTimeout)
	}
	if New("http://example", "tok", "test", WithTimeout(3*time.Second)).httpClient().Timeout != 3*time.Second {
		t.Fatal("WithTimeout wasn't applied")
	}

	// A Client built as a struct literal still gets a timeout.
	literal := &Client{BaseURL: "http://example"}
	if literal.httpClient().Timeout != DefaultTimeout {
		t.Fatal("struct-literal Client has no timeout")
	}
}

func TestSlowServerTimesOut(t *testing.T) {
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer ts.Close()
	defer close(release)

	start := time.Now()
	_, err := New(ts.URL, "tok", "test", WithTimeout(200*time.Millisecond)).GetSecret("app.key")
	if err == nil {
		t.Fatal("a server that never answers didn't time out")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("took %v to time out", elapsed)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var sawGET bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			sawGET = true
			io.WriteString(w, envelope(map[string]string{"key": "k", "value": "v"}))
			return
		}
		http.Redirect(w, r, "/moved", http.StatusMovedPermanently)
	}))
	defer ts.Close()

	_, err := New(ts.URL, "tok", "test").AddSecret("app.key", "x")
	if err == nil || !strings.Contains(err.Error(), "Unexpected Status 301") {
		t.Fatalf("AddSecret through a redirect = %v, want a 301 error", err)
	}
	if sawGET {
		t.Fatal("the redirect was followed (turning the POST into a GET)")
	}
}

func TestWithHTTPClient(t *testing.T) {
	var used bool
	hc := &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		used = true
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(envelope(map[string]bool{"healthy": true}))),
			Header:     make(http.Header),
		}, nil
	})}

	if ok, err := New("http://example", "", "test", WithHTTPClient(hc)).Health(); !ok || err != nil || !used {
		t.Fatalf("Health through a custom client = %v, %v (used %v)", ok, err, used)
	}
}
