# Changelog

All notable changes to CoveClient. Versions follow [semantic versioning](https://semver.org): from v1.0.0 on, existing code keeps compiling and working within v1.

## v1.0.0

**Upgrading from v0.2.0 needs small code changes:** `New` takes two arguments, and `Bootstrap()` is gone (see Removed). It also needs Cove v1.0.0 and a project token. What behaves differently is listed first; see [DOCUMENTATION.md](DOCUMENTATION.md#upgrading-from-v020).

### Behaviour changes

- Requests time out after 15 seconds (`WithTimeout` to change it) instead of waiting forever.
- The client uses its own `http.Client`: settings made on `http.DefaultClient` no longer apply (use `WithHTTPClient`). Redirects aren't followed.
- Error text keeps `Unexpected Status N` and adds Cove's explanation after it: `... Unexpected Status 404: not_found: secret not found`.
- Keys are checked before anything is sent; `?`, `#` or `../` in a key can no longer reach a different URL.

### Added

- `APIError` and sentinel errors for `errors.Is`: `ErrNotFound`, `ErrUnauthorized`, `ErrForbidden`, `ErrAlreadyExists`, `ErrInvalidKey`, `ErrBootstrapClosed`.
- `...Context` versions of every method.
- `GetSecrets(keys...)`: several secrets in one request (Cove's `POST /v0/batch`), naming every missing key.
- `LoadOrBootstrap(path)`: onboarding in one call (reads a saved token, or fetches and saves it safely).
- `WaitForReady(ctx)`: waits until Cove and its database are up.
- `ValidateKey`, `WithTimeout`, `WithHTTPClient`, doc comments, examples, and CI on Go 1.21 and the latest Go.

### Removed

- `Bootstrap()` and the `SecretValue` type. Use `LoadOrBootstrap(path)`, which also saves the token and sets it on the client.
- The platform name: `New(baseURL, token)` replaces `New(baseURL, clientSecret, platformName)`, and `Client.Platform` is gone. Cove 1.0 records a request under its token's name, so `X-Cove-Source` is no longer sent.
- `Client.ClientSecret` is now `Client.Token`.

### Works with

Cove v1.0.0 and later. It doesn't support Cove v0.2.0: upgrade Cove first, then the client.

## v0.2.0

The `/v0` API with the JSON envelope and a three-argument `New`.
