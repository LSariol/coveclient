# CoveClient Documentation

Full reference for CoveClient, the Go client library for [Cove](https://github.com/LSariol/Cove). Version v0.2.0, targets Cove API `v0`.

The [README](README.md) is a quick overview. This document covers every method's exact behavior, error handling, integration patterns for your other projects, and known issues.

For server-side behavior (routes, status codes, event log, bootstrap marker), see Cove's `DOCUMENTATION.md`.

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

- builds the `/v0/...` URLs,
- sets `Authorization: Bearer <secret>` and `X-Cove-Source: <platform>`,
- decodes Cove's `{"success", "data" | "error"}` response envelope,
- returns plain Go values (`string`, `bool`, `[]PublicSecretEntry`).

It has **no dependencies** outside the standard library and **no state** beyond the three fields on `Client`.

| File | Contents |
|---|---|
| `client.go` | `Client`, `New`, `decodeEnvelope`, all methods |
| `models.go` | `PublicSecretEntry`, `SecretValue`, and the unexported envelope/payload types |
| `client_test.go` | `httptest`-based unit tests |

---

## 2. Installation and versions

```bash
go get github.com/lsariol/coveclient@v0.2.0
```

- Module path: `github.com/lsariol/coveclient` (**lowercase**; the old `LSariol/coveclient` path was changed in `cbb631b`)
- Minimum Go: 1.21

| CoveClient | Cove API | Notes |
|---|---|---|
| v0.2.0 | `/v0/` with JSON envelope | Current. `New` takes 3 args. |
| v0.1.x and earlier | Pre-v0 (no `/v0/` prefix, no envelope) | Incompatible with Cove v0.2.0. |

### Upgrading from v0.1.x

- `New(baseURL, secret)` is now `New(baseURL, secret, platformName)`.
- The exported `Payload` and `Response` types were removed.
- The other method signatures didn't change. The wire formats changed, but the library handles that.
- Update the Cove server **first**. You can check it with `curl <cove>/v0/health`.

---

## 3. Creating a client

```go
import "github.com/lsariol/coveclient"

c := coveclient.New("http://cove:2100", clientSecret, "my-app")
```

| Parameter | Meaning |
|---|---|
| `baseURL` | Scheme + host + port, **with no trailing slash** (paths are added as `baseURL + "/v0/..."`). |
| `clientSecret` | Cove's `COVE_CLIENT_SECRET`. Can be `""` if you only call `Health` / `Bootstrap`. |
| `platformName` | Identifies your app in Cove's event log. It's **lowercased** by `New` and sent as `X-Cove-Source`. Use a stable name. |

`Client` has exported fields, so you can change them after construction (for example, set `ClientSecret` after `Bootstrap`):

```go
type Client struct {
    BaseURL      string
    ClientSecret string
    Platform     string   // already lowercased if set via New
}
```

`New` is the only place that lowercases `Platform`. If you set the field directly, the value is sent unchanged. `Client` is safe to use from multiple goroutines as long as you don't change its fields at the same time.

---

## 4. Method reference

Every method uses `http.DefaultClient`. Apart from `WaitForReady`, none of them take a `context.Context`.

| Method | HTTP | Auth | `X-Cove-Source` | Expected status | Returns |
|---|---|---|---|---|---|
| `Health()` | `GET /v0/health` | – | – | 200 | `(bool, error)` |
| `Auth()` | `GET /v0/auth` | ✓ | – | 200 | `error` |
| `Bootstrap()` | `GET /v0/bootstrap/lighthouse` | – | – | 200 | `(string, error)` |
| `GetSecret(id)` | `GET /v0/secrets/{id}` | ✓ | ✓ | 200 | `(string, error)` |
| `GetAllSecrets()` | `GET /v0/secrets` | ✓ | – | 200 | `([]PublicSecretEntry, error)` |
| `AddSecret(id, value)` | `POST /v0/secrets/{id}` | ✓ | ✓ | **201** | `(string, error)` |
| `UpdateSecret(id, value)` | `PATCH /v0/secrets/{id}` | ✓ | ✓ | 200 | `error` |
| `DeleteSecret(id)` | `DELETE /v0/secrets/{id}` | ✓ | ✓ | 200 | `error` |
| `LoadOrBootstrap(path)` | reads `path`, or `GET /v0/bootstrap/lighthouse` then `GET /v0/auth` | – | – | 200 | `(string, error)` |
| `WaitForReady(ctx)` | `GET /v0/ready` (falls back to `/v0/health`), repeated | – | – | 200 | `error` |

### `Health() (bool, error)`

Checks that the Cove HTTP server is up. It needs no credentials. It does **not** check Cove's database.

```go
ok, err := c.Health()
```

Returns `(true, nil)` when healthy. On any failure it returns `(false, err)`.

### `Auth() error`

Checks that `ClientSecret` is accepted. Returns `nil` on success. A wrong token returns `coveClient: Auth: Unexpected Status 401`.

### `Bootstrap() (string, error)`

Gets `COVE_CLIENT_SECRET` from Cove's one-time lighthouse endpoint. It needs no credentials.

```go
secret, err := c.Bootstrap()
if err == nil {
    c.ClientSecret = secret
}
```

- It only works while someone has opened the endpoint with `bootstrap open` in the Cove CLI (for 10 minutes by default, and closed again after one handout). Otherwise it returns `Unexpected Status 403`.
- It does **not** set `c.ClientSecret` or save the token for you. **Prefer `LoadOrBootstrap`**, which does both safely.

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

It uses `/v0/ready`, and falls back to `/v0/health` for Cove versions older than 1.0.0.

### `GetSecret(id string) (string, error)`

Returns the decrypted value. Each call adds 1 to the secret's `times_pulled` on the server and writes a `read` event tagged with your platform name.

```go
dbURL, err := c.GetSecret("myapp.database_url")
```

A missing key returns `Unexpected Status 404`.

### `GetAllSecrets() ([]PublicSecretEntry, error)`

Returns metadata for every secret, sorted by key. Values are never included. An empty vault returns a `nil` slice (Cove sends `null`), which is safe to `range` over.

### `AddSecret(id, value string) (string, error)`

Creates a secret. Returns Cove's message, for example `"myapp.token has been created."`. If the key already exists, Cove returns 500, which comes back as `coveClient: AddSecret: Unexpected Status 500`.

### `UpdateSecret(id, value string) error`

Replaces the value and adds 1 to the version. If the key doesn't exist, you get `Unexpected Status 500` (that's Cove's behavior, see its docs).

### `DeleteSecret(id string) error`

Deletes the secret. A missing key returns `Unexpected Status 404`. Cove keeps the encrypted value in its event log, so a deleted secret can be recovered on the server.

### Key rules

CoveClient doesn't validate or URL-escape `id`. Cove only accepts keys that:

- are 1–256 bytes long,
- contain only `A–Z a–z 0–9 - _ .` (no `/`, spaces, or `:`).

Other keys get a `400` from the server. A suggested naming convention is `<project>.<name>` or `<PROJECT>_<NAME>`, which makes the Cove CLI's `list <prefix>` filter useful.

---

## 5. Types

```go
// Returned by GetAllSecrets.
type PublicSecretEntry struct {
    Key          string    `json:"key"`
    Version      int       `json:"version"`
    TimesPulled  int       `json:"times_pulled"`
    DateAdded    time.Time `json:"created_at"`
    LastModified time.Time `json:"updated_at"`
}

// Bootstrap response payload. Exported, but you normally use Bootstrap()'s string return.
type SecretValue struct {
    Secret string `json:"secret"`
}
```

Unexported types in `models.go`: `secretPayload` (`{"value": ...}` request body), `apiResponse` (the envelope), and `apiError` (`{"type","message"}`).

---

## 6. Error handling

All errors are plain `error` values (no custom types or sentinel errors). There are three kinds:

| Source | Example message |
|---|---|
| Request build error (bad `BaseURL`) | `parse "http://%/v0/...": invalid URL escape "%/v"` |
| Network / transport | `Get "http://cove:2100/v0/health": dial tcp ...: connection refused` |
| Unexpected HTTP status | `coveClient: DeleteSecret: Unexpected Status 404` |
| Envelope `success: false` with an expected status | `coveClient: <type>: <message>` |
| Malformed JSON | `unexpected EOF`, etc. |

The status code is checked **before** the body is decoded. Cove always sends non-2xx status codes with its error envelope, so in practice **you get the status code but not Cove's `error.type` / `error.message`**. Use this table to tell errors apart:

| Status in error | Likely cause |
|---|---|
| 400 | Invalid key characters/length, missing `X-Cove-Source` (empty platform), bad body |
| 401 | Wrong/empty `ClientSecret`, or Cove hasn't loaded its secret yet (first-run issue on Cove) |
| 403 | `Bootstrap()` while Cove's bootstrap endpoint is closed (use `LoadOrBootstrap`, whose error explains why) |
| 404 | Key not found (GET/DELETE), or Cove failed to decrypt it |
| 405 | Method not allowed. Shouldn't happen unless routes drift. |
| 500 | Duplicate key on Add, missing key on Update, DB error |

`GetSecret` and `GetAllSecrets` leave the method name out of their status errors (`coveClient: Unexpected Status N`).

To match on status in code, today you have to check the string:

```go
if err != nil && strings.Contains(err.Error(), "Unexpected Status 404") { ... }
```

---

## 7. Integration patterns

### Loading secrets at startup

```go
func loadConfig() (*Config, error) {
    http.DefaultClient.Timeout = 10 * time.Second // see §11: no timeout by default

    c := coveclient.New(os.Getenv("COVE_URL"), os.Getenv("COVE_CLIENT_SECRET"), "myapp")

    if err := c.Auth(); err != nil {
        return nil, fmt.Errorf("cove auth: %w", err)
    }

    dbURL, err := c.GetSecret("MYAPP_DATABASE_URL")
    if err != nil {
        return nil, fmt.Errorf("get MYAPP_DATABASE_URL: %w", err)
    }
    return &Config{DatabaseURL: dbURL}, nil
}
```

Each `GetSecret` call counts as a pull and adds a row to Cove's event log. Fetch secrets once at startup and keep them in memory. Don't call it on every request.

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

### Network addressing

- Same Docker network as Cove (`spark`): `http://cove:2100`
- From the host: `http://localhost:2100`
- Local dev Cove: `http://localhost:2110`

### Handling the client secret

Keep `COVE_CLIENT_SECRET` in the consuming app's environment or `.env` file. Never hard-code it or commit it. Everyone who has it gets full read/write access to every secret in Cove.

---

## 8. Internals

Every method follows the same pattern:

```
http.NewRequest(method, BaseURL + "/v0/...", body)
  → set Authorization / Content-Type / X-Cove-Source
  → http.DefaultClient.Do(req)
  → defer resp.Body.Close()
  → if resp.StatusCode != expected → "coveClient: <Method>: Unexpected Status N"
  → decodeEnvelope(resp, &out)
  → return field from out
```

`decodeEnvelope(resp, out)`:

1. JSON-decodes the body into `apiResponse` (`Data` is kept as `json.RawMessage`).
2. If `success` is false, returns `coveClient: <type>: <message>`, or a status-based error if `error` is missing.
3. If `out` isn't nil, unmarshals `Data` into it.

`AddSecret` and `UpdateSecret` send `{"value": "..."}` with `Content-Type: application/json`. The other methods send no body.

To add a method, follow the same pattern. Keep the `coveClient: <Method>:` error prefix and don't add external dependencies.

---

## 9. Testing

```bash
go test ./...
```

- All tests are in `client_test.go` (`package coveclient`, so they can reach unexported types).
- Each test starts an `httptest.NewServer` that checks the method, path, `Authorization`, and `X-Cove-Source`, then returns a canned envelope.
- Helpers: `newTestClient(ts, secret)` creates a client with platform `"test"`. `envelope(data)` builds `{"success":true,"data":...}`.
- `TestHTTPDoError_Propagates` swaps `http.DefaultClient.Transport` to simulate transport errors, so don't add `t.Parallel()` to tests in this package.

The tests cover each method's success path and wrong-status path, plus malformed JSON and bad-URL cases for some methods. There are no integration tests against a real Cove server.

### Manual testing

`main/` is gitignored and holds a local scratch program. It currently contains a hard-coded client secret. Keep it out of git, and consider reading the secret from an env var instead.

---

## 10. Keeping in sync with Cove

These must match Cove's server code. If you change either repo, check the other:

| Contract | Cove location | CoveClient location |
|---|---|---|
| Route paths, `/v0` prefix | `internal/server/handlers.go` `defineRoutes` | Each method's URL string (8 places) |
| Response envelope | `internal/server/models.go` `APIResponse` | `models.go` `apiResponse` |
| Success status codes | `internal/server/secrets.go` | Each method's `StatusCode` check |
| Secret list JSON fields | `SecretSummary` | `PublicSecretEntry` tags |
| Request body `{"value"}` | `postSecret` / `patchSecret` | `secretPayload` |
| `X-Cove-Source` requirement | `handleSecretID` | Set on `/v0/secrets/{id}` methods |

Release process: update Cove first, then CoveClient, then tag CoveClient (`git tag vX.Y.Z && git push --tags`) and `go get` the new tag in each consuming project. A breaking change should bump the minor version while in `v0`.

---

## 11. Known issues and gotchas

> See [IMPROVEMENTS.md](IMPROVEMENTS.md) for ratings (criticality, effort, improvement), proposed fixes, and a suggested order of work.

1. **No timeout.** `http.DefaultClient` has no timeout, so a hung Cove can block your app forever. Set `http.DefaultClient.Timeout` (this affects your whole process) until the library supports its own `*http.Client`.
2. **No `context.Context` support.** Requests can't be cancelled or given a deadline per call.
3. **Server error details are lost.** Status is checked before the envelope is decoded, so Cove's `error.type` / `error.message` never reach you. `decodeEnvelope`'s error branch only runs in the unlikely case of a 2xx response with `success: false`.
4. **No typed errors.** You can't use `errors.Is` to check for "not found" or "already exists". You have to match on the message string.
5. **`id` isn't URL-escaped or validated on the client.** Invalid keys only fail with a server `400`.
6. **A trailing slash in `baseURL`** produces `//v0/...`. Go's `ServeMux` redirects that with a `301`. Following the redirect turns POST/PATCH/DELETE into GET or drops the body, so you get confusing errors.
7. **Empty `platformName`** leaves out `X-Cove-Source`, and every `/v0/secrets/{id}` call fails with `400`.
8. **Only `New` lowercases `Platform`.** If you set `c.Platform` directly, its case is kept.
9. **`GetSecret` and `GetAllSecrets` error messages** leave out the method name (`coveClient: Unexpected Status N`), unlike the other methods.
10. **`TestHTTPDoError_Propagates`** saves `http.DefaultTransport` but assigns `http.DefaultClient.Transport`, and restores it to `DefaultTransport` rather than the original `nil`. This is harmless, but it changes global state.
11. **The `/v0` prefix is hard-coded** in every method, so a Cove API bump means editing each URL.
