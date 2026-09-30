# CoveClient

A lightweight, dependency-free Go client for [Cove](https://github.com/LSariol/cove) — a self-hosted secret management service.

> Full documentation (internals, deployment, error reference, known issues): [DOCUMENTATION.md](DOCUMENTATION.md)

> **Who needs this library?** In the standard setup, Lighthouse injects each project's secrets as environment variables when it deploys it, so most projects don't use CoveClient at all. It's for **Lighthouse** itself and for **projects that change secrets** (e.g. botsuite refreshing tokens), which get `COVE_URL=http://cove:2100` and their own `COVE_TOKEN`. See "Connecting a project" in Cove's DOCUMENTATION.md.

## Features

- Full CRUD operations on secrets, plus `GetSecrets` to fetch several at once
- One-call onboarding (`LoadOrBootstrap`) and start-up waiting (`WaitForReady`)
- Errors that say what went wrong, and that you can check with `errors.Is`
- A 15-second request timeout by default; every method has a `...Context` version
- Sends `X-Cove-Source` for per-request audit logging
- Zero external dependencies; Go 1.21+

## Installation

```bash
go get github.com/lsariol/coveclient
```

## Usage

```go
import "github.com/lsariol/coveclient"

c := coveclient.New("http://cove.internal:2100", "<COVE_CLIENT_SECRET>", "my-app")
```

The token can be Cove's master token or a **project token** made with `token create` in the Cove CLI, which only reaches the keys it was given. The client works the same with either.

The third argument (`platformName`) is sent as the `X-Cove-Source` header on every secret operation and is recorded in Cove's event log. If it's empty, the program's name is used. (With a project token, Cove records the token's name instead.)

Options go after it:

```go
c := coveclient.New(url, token, "my-app",
    coveclient.WithTimeout(5*time.Second),  // default 15s
    coveclient.WithHTTPClient(myHTTPClient), // e.g. for a proxy; its own timeout applies
)
```

A typical start-up:

```go
ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
defer cancel()
if err := c.WaitForReady(ctx); err != nil {
    log.Fatal(err)
}
if _, err := c.LoadOrBootstrap("/data/cove-token"); err != nil {
    log.Fatal(err)
}
secrets, err := c.GetSecrets("my-app.db-url", "my-app.api-key")
if err != nil {
    log.Fatal(err) // names every missing key
}
```

A runnable version is in [examples/basic](examples/basic/main.go).

---

## Methods

Every method below except `LoadOrBootstrap` and `WaitForReady` has a `...Context` version that takes a `context.Context` first, e.g. `GetSecretContext(ctx, key)`. The plain versions use `context.Background()`.

### `Health() (bool, error)`
Unauthenticated. Returns `true` if the server is reachable and healthy.

```go
healthy, err := c.Health()
```

### `Auth() error`
Authenticated. Returns `nil` if the client secret is valid.

```go
err := c.Auth()
```

### `LoadOrBootstrap(path string) (string, error)`
Onboarding in one call: reads the token from `path`, or fetches it from Cove's bootstrap endpoint (open it with `bootstrap open` in the Cove CLI), saves it to `path` (`600`), and sets it on the client. Call it on every start. If Cove refuses, the error wraps `ErrBootstrapClosed`.

```go
token, err := c.LoadOrBootstrap("/data/cove-token")
```

### `WaitForReady(ctx) error`
Waits until Cove and its database are up, retrying until `ctx` is done.

```go
err := c.WaitForReady(ctx)
```

### `Bootstrap() (string, error)`
Unauthenticated. Returns the `COVE_CLIENT_SECRET` while Cove's bootstrap endpoint is open (`bootstrap open` in the Cove CLI). Doesn't save it; prefer `LoadOrBootstrap`.

```go
secret, err := c.Bootstrap()
```

### `GetSecret(key string) (string, error)`
Returns the decrypted value of a secret by key.

```go
value, err := c.GetSecret("my-api-key")
```

### `GetSecrets(keys ...string) (map[string]string, error)`
Returns several secrets, keyed by name. If any are missing, the error names all of them and matches `ErrNotFound`.

```go
s, err := c.GetSecrets("my-app.db-url", "my-app.api-key")
dbURL := s["my-app.db-url"]
```

### `GetAllSecrets() ([]PublicSecretEntry, error)`
Returns metadata for all secrets. Values are never included.

```go
entries, err := c.GetAllSecrets()
for _, e := range entries {
    fmt.Println(e.Key, e.Version, e.TimesPulled)
}
```

### `AddSecret(key, value string) (string, error)`
Creates a new secret. Returns the server's confirmation message.

```go
msg, err := c.AddSecret("my-api-key", "super-secret-value")
```

### `UpdateSecret(key, value string) error`
Updates an existing secret's value. Increments its version on the server.

```go
err := c.UpdateSecret("my-api-key", "new-value")
```

### `DeleteSecret(key string) error`
Deletes a secret. Cove keeps its history, so it can be brought back with `restore` in the Cove CLI.

```go
err := c.DeleteSecret("my-api-key")
```

### `ValidateKey(key string) error`
Checks a key against Cove's rule: 1–256 characters, each a letter, digit, `.`, `_` or `-`. Every method that takes a key checks it before sending anything.

---

## Errors

When Cove answers with an error, you get an `*APIError`. Its text keeps the `Unexpected Status N` wording of earlier versions and adds Cove's explanation:

```
coveClient: GetSecret: Unexpected Status 404: not_found: secret not found
```

Check for common cases with `errors.Is`:

| Error | When |
|---|---|
| `ErrNotFound` | 404: no secret with that key |
| `ErrUnauthorized` | 401: the token is missing or wrong |
| `ErrForbidden` | 403: a project token that doesn't cover this key |
| `ErrAlreadyExists` | 409: `AddSecret` on a key that exists |
| `ErrInvalidKey` | the key breaks Cove's rule (checked before sending) |
| `ErrBootstrapClosed` | Cove refused to hand out the token |

```go
value, err := c.GetSecret("my-api-key")
if errors.Is(err, coveclient.ErrNotFound) {
    // create it
}

var apiErr *coveclient.APIError
if errors.As(err, &apiErr) {
    log.Println(apiErr.StatusCode, apiErr.Type, apiErr.Message)
}
```

---

## Types

```go
type PublicSecretEntry struct {
    Key          string
    Version      int
    TimesPulled  int
    DateAdded    time.Time
    LastModified time.Time
}
```

---

## Notes

- All routes target the Cove `/v0/` API. If Cove upgrades to `/v1/`, update to a matching version of this module.
- The client uses its own `http.Client`, not `http.DefaultClient`: requests time out after 15 seconds, and redirects aren't followed. Settings made on `http.DefaultClient` don't apply; use `WithHTTPClient` instead.
- The `Bootstrap` endpoint is one-use only by design. See the [Cove docs](https://github.com/LSariol/cove) for the bootstrap flow.
