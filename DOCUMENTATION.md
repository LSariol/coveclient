# CoveClient Documentation

Full reference for CoveClient, the Go client library for [Cove](https://github.com/LSariol/Cove). Version v1.0.0, targets Cove API `v0`.

The [README](README.md) is a quick overview. This document covers every method's exact behavior, error handling, integration patterns for your other projects, and known issues.

For server-side behavior (routes, status codes, event log, bootstrap gate), see Cove's `DOCUMENTATION.md`.

> **Who needs this library?** In the standard setup, Lighthouse injects each project's secrets as environment variables when it deploys it, so most projects don't use CoveClient at all. It's for **Lighthouse** itself and for **projects that change secrets** (e.g. botsuite refreshing tokens), which get `COVE_URL=http://cove:2100` and their own `COVE_TOKEN`. See "Connecting a project" in Cove's DOCUMENTATION.md.

---

## Contents

1. [Overview](#1-overview)
2. [Installation and versions](#2-installation-and-versions)
3. [Creating a client](#3-creating-a-client)
4. [Method reference](#4-method-reference)
5. [Types](#5-types)
6. [Error handling](#6-error-handling)
7. [Integration patterns](#7-integration-patterns)
8. [Internals](#8-internals)
9. [Testing](#9-testing)
10. [Keeping in sync with Cove](#10-keeping-in-sync-with-cove)
11. [Known issues and gotchas](#11-known-issues-and-gotchas)

---

## 1. Overview

CoveClient wraps Cove's HTTP API in a small Go API. It:

- checks keys and builds the `/v0/...` URLs,
- sets `Authorization: Bearer <secret>` and `X-Cove-Source: <platform>`,
- sends requests with its own `http.Client` (15-second timeout, no redirects),
- decodes Cove's `{"success", "data" | "error"}` response envelope,
- returns plain Go values (`string`, `bool`, `map[string]string`, `[]PublicSecretEntry`), and errors you can check with `errors.Is`.

It has **no dependencies** outside the standard library.

| File | Contents |
|---|---|
| `doc.go` | The package overview shown by `go doc` and pkg.go.dev |
| `client.go` | `Client`, `New`, options, the shared `do` request helper, and every method with its `...Context` version |
| `secrets.go` | `GetSecrets` |
| `keys.go` | `ValidateKey`, `ErrInvalidKey`, and building a secret's path |
| `errors.go` | `APIError` and the sentinel errors |
| `onboarding.go` | `LoadOrBootstrap`, `WaitForReady`, `ErrBootstrapClosed` |
| `models.go` | `PublicSecretEntry` and the unexported envelope/payload types |
| `*_test.go` | `httptest`-based unit tests; `example_test.go` holds the examples shown in the docs |
| `examples/basic/` | A small program that reads secrets using settings from environment variables |

---

## 2. Installation and versions

```bash
go get github.com/lsariol/coveclient@v1.0.0
```

- Module path: `github.com/lsariol/coveclient` (**lowercase**; the old `LSariol/coveclient` path was changed in `cbb631b`)
- Minimum Go: 1.21 (CI tests on 1.21 and the latest Go)

| CoveClient | Cove | Notes |
|---|---|---|
| v1.0.0 | v1.0.0 and later | Current. Needs Cove 1.0.0: upgrade Cove first, then the client. |
| v0.2.0 | `/v0/` with JSON envelope | `New` takes 3 args. |
| v0.1.x and earlier | Pre-v0 (no `/v0/` prefix, no envelope) | Incompatible with Cove v0.2.0 and later. |

### Upgrading from v0.2.0

One code change may be needed: `Bootstrap()` and the `SecretValue` type are gone, so replace a `Bootstrap()` call with `LoadOrBootstrap(path)`, which also saves the token and sets it on the client. Every other v0.2.0 call compiles and works the same way. What changes:

- **Timeouts.** Requests fail after 15 seconds instead of waiting forever. Change it with `WithTimeout`.
- **`http.DefaultClient` is no longer used.** If you set `http.DefaultClient.Timeout` (or its `Transport`) for CoveClient's sake, it no longer has any effect; pass `WithTimeout` or `WithHTTPClient` to `New` instead.
- **Error text is longer.** `Unexpected Status 404` becomes `Unexpected Status 404: not_found: secret not found`. Code that checks `strings.Contains(err.Error(), "Unexpected Status 404")` still works, but `errors.Is(err, coveclient.ErrNotFound)` is better.
- **Keys are checked first.** A key with characters Cove doesn't allow fails with `ErrInvalidKey` without a request. Before, it either got a `400` from Cove or, for `?`, `#` or `../`, silently reached a different URL.
- **An empty `platformName`** now uses the program's name instead of making every secret call fail.

CoveClient 1.0.0 needs Cove 1.0.0 or later (it uses `/v0/ready` and `/v0/batch`, which older versions don't have). Upgrade Cove first, then the client.

---

## 3. Creating a client

```go
import "github.com/lsariol/coveclient"

c := coveclient.New("http://cove:2100", clientSecret, "my-app")
```

| Parameter | Meaning |
|---|---|
| `baseURL` | Scheme + host + port, e.g. `http://cove:2100`. A trailing slash is ignored. |
| `clientSecret` | Cove's `COVE_CLIENT_SECRET`. Can be `""` if you'll call `LoadOrBootstrap`, or only `Health`. |
| `platformName` | Identifies your app in Cove's event log. It's **lowercased** by `New` and sent as `X-Cove-Source`. Use a stable name. If empty, the program's file name is used (e.g. `lighthouse`). |
| `opts...` | Optional settings, below. |

| Option | Effect |
|---|---|
| `WithTimeout(d)` | How long a request may take before it fails. Default `DefaultTimeout` (15s). |
| `WithHTTPClient(hc)` | Send requests with your own `*http.Client` (proxy, custom TLS, tracing). Its own timeout and redirect settings apply instead of CoveClient's. |

`Client` has exported fields, so you can change them after construction (for example, `LoadOrBootstrap` sets `ClientSecret`):

```go
type Client struct {
    BaseURL      string
    ClientSecret string
    Platform     string // already lowercased if set via New
    // unexported: the http.Client and timeout
}
```

`New` is the only place that lowercases `Platform`. If you set the field directly, the value is sent unchanged. A `Client` built as a struct literal instead of with `New` still gets the default timeout. `Client` is safe to use from multiple goroutines as long as you don't change its fields at the same time.

---

## 4. Method reference

Every method except `LoadOrBootstrap` and `WaitForReady` has a `...Context` version that takes a `context.Context` first (`GetSecretContext(ctx, key)`, `AuthContext(ctx)`, ...). Use it to cancel a request or give it a deadline. The plain versions call it with `context.Background()`; the client's timeout applies either way.

| Method | HTTP | Auth | `X-Cove-Source` | Expected status | Returns |
|---|---|---|---|---|---|
| `Health()` | `GET /v0/health` | – | – | 200 | `(bool, error)` |
| `Auth()` | `GET /v0/auth` | ✓ | – | 200 | `error` |
| `GetSecret(key)` | `GET /v0/secrets/{key}` | ✓ | ✓ | 200 | `(string, error)` |
| `GetSecrets(keys...)` | `POST /v0/batch` (up to 100 keys per request) | ✓ | ✓ | 200 | `(map[string]string, error)` |
| `GetAllSecrets()` | `GET /v0/secrets` | ✓ | – | 200 | `([]PublicSecretEntry, error)` |
| `AddSecret(key, value)` | `POST /v0/secrets/{key}` | ✓ | ✓ | **201** | `(string, error)` |
| `UpdateSecret(key, value)` | `PATCH /v0/secrets/{key}` | ✓ | ✓ | 200 | `error` |
| `DeleteSecret(key)` | `DELETE /v0/secrets/{key}` | ✓ | ✓ | 200 | `error` |
| `LoadOrBootstrap(path)` | reads `path`, or `GET /v0/bootstrap/lighthouse` then `GET /v0/auth` | – | – | 200 | `(string, error)` |
| `WaitForReady(ctx)` | `GET /v0/ready`, repeated | – | – | 200 | `error` |

### `Health() (bool, error)`

Checks that the Cove HTTP server is up. It needs no credentials. It does **not** check Cove's database (`WaitForReady` does).

```go
ok, err := c.Health()
```

Returns `(true, nil)` when healthy. On any failure it returns `(false, err)`.

### `Auth() error`

Checks that `ClientSecret` is accepted. Returns `nil` on success. A wrong token returns an error matching `ErrUnauthorized`:

```
coveClient: Auth: Unexpected Status 401: invalid_token: the provided token is invalid
```

### `LoadOrBootstrap(path string) (string, error)`

Gets this client's token and sets `c.ClientSecret`. Call it on every start:

```go
c := coveclient.New("http://cove:2100", "", "lighthouse")
token, err := c.LoadOrBootstrap("/data/cove-token")
if errors.Is(err, coveclient.ErrBootstrapClosed) {
    log.Fatal("Run `bootstrap open` in the Cove CLI, then restart: ", err)
}
```

- **The file at `path` exists:** the token is read from it. No request is made.
- **It doesn't:** the token is fetched from Cove's bootstrap endpoint, **saved to `path` immediately** (permissions `600`, written to a temporary file and renamed, so a crash can't leave a partial file), then checked with `Auth()`.
- **Cove refuses** (endpoint closed, window expired, or address not allowed): the error wraps `ErrBootstrapClosed` and includes Cove's reason.
- If the client crashes right after receiving the token, Cove hands it to the same address again for 2 minutes, so the next start still succeeds.
- To bootstrap again (e.g. after the token was rotated), delete the file and run `bootstrap open`.

### `WaitForReady(ctx context.Context) error`

Waits until Cove is up **and** its database is reachable, retrying with a growing delay (up to 5 seconds) until `ctx` is done. Use it at startup when your app and Cove start together:

```go
ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
defer cancel()
if err := c.WaitForReady(ctx); err != nil {
    log.Fatal(err) // "coveClient: Cove at http://cove:2100 wasn't ready: context deadline exceeded"
}
```

It uses `/v0/ready`, which also checks Cove's database.

### `GetSecret(key string) (string, error)`

Returns the decrypted value. Each call adds 1 to the secret's `times_pulled` on the server and writes a `read` event tagged with your platform name.

```go
dbURL, err := c.GetSecret("MYAPP_DATABASE_URL")
```

- A missing key returns an error matching `ErrNotFound`.
- If Cove answers with a different key than the one asked for, it's an error and no value is returned.

### `GetSecrets(keys ...string) (map[string]string, error)`

Fetches several secrets and returns them keyed by name. Duplicate keys are fetched once.

```go
s, err := c.GetSecrets("MYAPP_DATABASE_URL", "MYAPP_TMDB_API_KEY")
if err != nil {
    log.Fatal(err) // coveClient: GetSecrets: not found: MYAPP_TMDB_API_KEY
}
dbURL := s["MYAPP_DATABASE_URL"]
```

- **One request** for all of them (`POST /v0/batch`). More than 100 keys are split into several requests.
- **All or nothing.** If any are missing, the error names **all** of them and matches `ErrNotFound`, so one start-up tells you everything to add. If the token can't read one of them, the error matches `ErrForbidden`; Cove deliberately doesn't say which one (its server log does).
- Every key is checked with `ValidateKey` before any request.
- Each key still counts as a read in Cove.

### `GetAllSecrets() ([]PublicSecretEntry, error)`

Returns metadata for every secret, sorted by key. Values are never included. An empty vault returns an empty or `nil` slice, which is safe to `range` over.

### `AddSecret(key, value string) (string, error)`

Creates a secret. Returns Cove's message, for example `"MYAPP_GITHUB_TOKEN has been created."`. If the key already exists, the error matches `ErrAlreadyExists`.

### `UpdateSecret(key, value string) error`

Replaces the value and adds 1 to the version. If the key doesn't exist, the error matches `ErrNotFound`.

### `DeleteSecret(key string) error`

Deletes the secret. A missing key returns an error matching `ErrNotFound`. Cove keeps the encrypted value in its event log, so a deleted secret can be brought back with `restore` in the Cove CLI.

### `ValidateKey(key string) error` and key rules

Cove only accepts keys that:

- are 1–256 characters long,
- contain only `A–Z a–z 0–9 - _ .` (no `/`, spaces, `:`, `?` or `#`).

Every method that takes a key checks it with `ValidateKey` first. A bad key returns an error matching `ErrInvalidKey`, and nothing is sent. You can also call `ValidateKey` yourself, e.g. in a unit test over your project's key names.

Keys follow Cove's naming standard, **`PROJECT_PLATFORM_TYPE`** (e.g. `BOTSUITE_TWITCH_CLIENT_ID`, `SHARED_TMDB_API_KEY`): capitals, digits and `_`, so they also work as `${...}` variables in a compose file. See "Key naming standard" in Cove's DOCUMENTATION.md.

---

## 5. Types

```go
// Returned by GetAllSecrets.
type PublicSecretEntry struct {
    Key          string    `json:"key"`
    Version      int       `json:"version"`      // goes up by one on each update
    TimesPulled  int       `json:"times_pulled"` // how many times it has been read
    DateAdded    time.Time `json:"created_at"`
    LastModified time.Time `json:"updated_at"`
}

// Returned when Cove answers with an unexpected status. See §6.
type APIError struct {
    Method     string // the Client method that failed, e.g. "GetSecret"
    StatusCode int
    Type       string // Cove's error type, e.g. "not_found"
    Message    string // Cove's explanation
}
```

Unexported types in `models.go`: `secretPayload` (`{"value": ...}` request body), `apiResponse` (the envelope), and `apiError` (`{"type","message"}`).

---

## 6. Error handling

Every error starts with `coveClient:` except network errors, which come straight from Go's `net/http`.

| Source | Example message |
|---|---|
| Invalid key (no request sent) | `coveClient: invalid key: "my key" contains ' '; only letters, digits, '.', '_' and '-' are allowed` |
| Request build error (bad `BaseURL`) | `parse "http://%/v0/...": invalid URL escape "%/v"` |
| Network / transport | `Get "http://cove:2100/v0/health": dial tcp ...: connection refused` |
| Timeout | `Get "http://cove:2100/v0/secrets/x": context deadline exceeded (Client.Timeout exceeded while awaiting headers)` |
| Unexpected HTTP status (`*APIError`) | `coveClient: DeleteSecret: Unexpected Status 404: not_found: secret not found` |
| Envelope `success: false` with an expected status | `coveClient: <type>: <message>` |
| Malformed JSON | `unexpected EOF`, etc. |

### Checking for a kind of error

Use `errors.Is` with the sentinel errors:

| Sentinel | Matches |
|---|---|
| `ErrNotFound` | `404` (no such secret); also `GetSecrets` with missing keys |
| `ErrUnauthorized` | `401` (missing or wrong token) |
| `ErrForbidden` | `403 forbidden_key` (a project token that can't read or change this key) |
| `ErrAlreadyExists` | `409` (`AddSecret` on an existing key) |
| `ErrInvalidKey` | a key refused by `ValidateKey`, or Cove's `400 invalid_key` |
| `ErrBootstrapClosed` | `403` from the bootstrap endpoint (`bootstrap_locked`, `bootstrap_expired`, `bootstrap_forbidden`) |

```go
value, err := c.GetSecret("MYAPP_TMDB_API_KEY")
switch {
case errors.Is(err, coveclient.ErrNotFound):
    // create it
case err != nil:
    return err
}
```

To read the details, use `errors.As`:

```go
var apiErr *coveclient.APIError
if errors.As(err, &apiErr) {
    log.Println(apiErr.StatusCode, apiErr.Type, apiErr.Message)
}
```

If the response body isn't Cove's JSON (for example an HTML error page from a proxy), `Type` and `Message` are empty and the text is just `coveClient: <Method>: Unexpected Status N`.

### What each status usually means

| Status | Likely cause |
|---|---|
| 400 | Invalid key (normally caught before sending), missing `X-Cove-Source`, bad body |
| 401 | Wrong/empty `ClientSecret`, or Cove hasn't loaded its secret yet |
| 403 | A project token that doesn't cover the key (`forbidden_key`), or the bootstrap endpoint is closed, expired, or not allowed from this address |
| 404 | No secret with that key |
| 405 | Method not allowed. Shouldn't happen unless routes drift. |
| 409 | `AddSecret` on a key that exists |
| 500 | Database error, or `decrypt_error` (the encryption key changed on the server) |
| 503 | Cove is up but its database isn't (`/v0/ready`) |

---

## 7. Integration patterns

### Loading secrets at startup

For a project that writes back (the others get their values injected and don't need this):

```go
func loadConfig(ctx context.Context) (*Config, error) {
    c := coveclient.New(os.Getenv("COVE_URL"), os.Getenv("COVE_TOKEN"), "myapp")

    s, err := c.GetSecretsContext(ctx, "MYAPP_DATABASE_URL", "MYAPP_API_KEY")
    if err != nil {
        return nil, fmt.Errorf("load secrets from Cove: %w", err)
    }
    return &Config{DatabaseURL: s["MYAPP_DATABASE_URL"], APIKey: s["MYAPP_API_KEY"]}, nil
}
```

Each secret read counts as a pull and adds a row to Cove's event log. Fetch secrets once at startup and keep them in memory. Don't fetch them on every request.

### Waiting for Cove on startup (Docker)

If your app starts alongside Cove, wait for it first:

```go
ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
defer cancel()
if err := c.WaitForReady(ctx); err != nil {
    return err
}
```

Or in compose, use `depends_on: { cove: { condition: service_healthy } }`, since Cove defines a healthcheck.

### First-boot bootstrap

```go
c := coveclient.New(coveURL, "", "lighthouse")
if err := c.WaitForReady(ctx); err != nil {
    return err
}
if _, err := c.LoadOrBootstrap("/data/cove-token"); err != nil {
    return err // wraps ErrBootstrapClosed if Cove's endpoint isn't open
}
```

The first time, run `bootstrap open` in the Cove CLI before starting the client. Keep `/data` on a persistent volume, so the token survives restarts.

A complete, runnable version is `examples/basic` (`COVE_URL=... go run ./examples/basic KEY...`).

### Network addressing

- **Prod: `http://cove:2100`, from a container on the `spark` Docker network.** Cove publishes no port, so this is the only way in; a project on another network must join `spark`.
- Local dev Cove: `http://localhost:2110`

### Project tokens

Cove 1.0.0 can give each project its own token, limited to certain keys (`token create botsuite --allow 'BOTSUITE_*'` in the Cove CLI). Nothing changes in your code: pass the project token wherever you passed `COVE_CLIENT_SECRET`, or let `LoadOrBootstrap` fetch it (`bootstrap open lighthouse` hands out Lighthouse's own token). Differences you may notice:

- A key outside the token's access fails with an error matching `ErrForbidden`, whether or not the key exists.
- `GetAllSecrets` lists only the keys the token can read.
- Cove's event log records the token's name as the source; `platformName` is ignored.

### Handling the client secret

Keep `COVE_CLIENT_SECRET` in the consuming app's environment, `.env` file, or a `LoadOrBootstrap` token file. Never hard-code it or commit it. Everyone who has it gets full read/write access to every secret in Cove.

---

## 8. Internals

Every method builds a `request` (name, method, path, body, which headers, expected status) and passes it to `do`:

```
secretPath(key)                         → ValidateKey, then "/v0/secrets/" + url.PathEscape(key)
do(ctx, request, &out)
  → http.NewRequestWithContext(ctx, method, c.url(path), body)   // c.url trims a trailing "/"
  → set Content-Type / Authorization / X-Cove-Source (c.source(): Platform or the program name)
  → c.httpClient().Do(req)                                       // own client: timeout, no redirects
  → if resp.StatusCode != want → newAPIError(name, resp)         // reads Cove's error envelope
  → decodeEnvelope(resp, &out)
```

`decodeEnvelope(resp, out)`:

1. JSON-decodes the body into `apiResponse` (`Data` is kept as `json.RawMessage`).
2. If `success` is false, returns `coveClient: <type>: <message>`, or a status-based error if `error` is missing.
3. If `out` isn't nil, unmarshals `Data` into it.

Redirects aren't followed because Cove never redirects on purpose, and following one would turn a POST, PATCH or DELETE into a GET.

`LoadOrBootstrap` and `WaitForReady` (in `onboarding.go`) make their own requests with `c.httpClient()`, because they handle statuses differently (a refused bootstrap, or Cove not being ready yet).

To add a method: write a `...Context` version that calls `c.do`, and a plain version that calls it with `context.Background()`. Keep the `coveClient: <Method>:` error prefix and don't add external dependencies.

---

## 9. Testing

```bash
go test ./...
```

- Tests are `package coveclient`, so they can reach unexported code. `example_test.go` is `package coveclient_test` and shows the public API as a user sees it; `ExampleValidateKey` checks its output, the others only compile.
- Each test starts an `httptest.NewServer` that checks the request and returns a canned response.
- Helpers: `newTestClient(ts, secret)` creates a client with platform `"test"`. `envelope(data)` builds `{"success":true,"data":...}`. `coveError(status, type, message)` answers like a failing Cove.
- No test changes global state, so tests can run in parallel.
- CI (`.github/workflows/ci.yml`) runs gofmt, `go vet` and `go test -race` on Go 1.21 and the latest Go.

There are no integration tests against a real Cove server in this repo. Cove's own CI runs its API against a real Postgres.

### Manual testing

`main/` is gitignored and holds a local scratch program. It contains a hard-coded client secret: keep it out of git, and rotate that token. `examples/basic` does the same job reading its settings from environment variables.

---

## 10. Keeping in sync with Cove

These must match Cove's server code. If you change either repo, check the other:

| Contract | Cove location | CoveClient location |
|---|---|---|
| Route paths, `/v0` prefix | `internal/server/routes.go` `defineRoutes` | Each method's `path`, `secretPath` in `keys.go` |
| Response envelope | `internal/server/api_types.go` `APIResponse`, `APIError` | `models.go` `apiResponse`, `apiError` |
| Success status codes | `internal/server/secrets.go` | Each method's `want` |
| Error types (`not_found`, `bootstrap_*`, ...) | `writeError` calls in `internal/server/` | `APIError.Is` in `errors.go` |
| Key rules | `internal/vault/keys.go` | `ValidateKey` in `keys.go` |
| Secret list JSON fields | `SecretSummary` | `PublicSecretEntry` tags |
| Request body `{"value"}` | `postSecret` / `patchSecret` | `secretPayload` |
| `X-Cove-Source` requirement | `handleSecretID` | Set on `/v0/secrets/{key}` methods |
| Batch read (`POST /v0/batch`, 100-key limit, `error.keys`) | `internal/server/batch.go` | `batch` and `maxBatchKeys` in `secrets.go`; `APIError.Keys` |

Release process: update Cove first, then CoveClient, then tag CoveClient (`git tag vX.Y.Z && git push --tags`) and `go get` the new tag in each consuming project. From v1, a breaking change needs a new major version (`/v2` module path), so avoid them.

---

## 11. Known issues and gotchas

1. **Only `New` lowercases `Platform`.** If you set `c.Platform` directly, its case is kept.
2. **The `/v0` prefix is written into each method's path**, so a Cove API bump means editing each one (and a new major version of this module).
3. **`LoadOrBootstrap` and `WaitForReady` have no `...Context` twin for everything.** `WaitForReady` takes a context; `LoadOrBootstrap` doesn't, but each of its requests is bounded by the client's timeout.
