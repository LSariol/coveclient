# CoveClient

A lightweight, dependency-free Go client for [Cove](https://github.com/LSariol/cove) — a self-hosted secret management service.

> Full documentation (internals, deployment, error reference, known issues): [DOCUMENTATION.md](DOCUMENTATION.md)

## Features

- Full CRUD operations on secrets
- Health check and authentication verification
- One-call bootstrap for automated first-boot setup
- Sends `X-Cove-Source` for per-request audit logging
- Zero external dependencies

## Installation

```bash
go get github.com/lsariol/coveclient
```

## Usage

```go
import "github.com/lsariol/coveclient"

c := coveclient.New("http://cove.internal:2100", "<COVE_CLIENT_SECRET>", "my-app")
```

The third argument (`platformName`) is sent as the `X-Cove-Source` header on every secret operation and is recorded in Cove's event log.

---

## Methods

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

### `GetSecret(id string) (string, error)`
Returns the decrypted value of a secret by key.

```go
value, err := c.GetSecret("my-api-key")
```

### `GetAllSecrets() ([]PublicSecretEntry, error)`
Returns metadata for all secrets. Values are never included.

```go
entries, err := c.GetAllSecrets()
for _, e := range entries {
    fmt.Println(e.Key, e.Version, e.TimesPulled)
}
```

### `AddSecret(id, value string) (string, error)`
Creates a new secret. Returns the server's confirmation message.

```go
msg, err := c.AddSecret("my-api-key", "super-secret-value")
```

### `UpdateSecret(id, value string) error`
Updates an existing secret's value. Increments its version on the server.

```go
err := c.UpdateSecret("my-api-key", "new-value")
```

### `DeleteSecret(id string) error`
Deletes a secret permanently.

```go
err := c.DeleteSecret("my-api-key")
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
- `http.DefaultClient` is used with no timeout. Set `http.DefaultClient.Timeout` or use a reverse proxy with timeouts if needed.
- The `Bootstrap` endpoint is one-use only by design. See the [Cove docs](https://github.com/LSariol/cove) for the bootstrap flow.
