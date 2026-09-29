# CoveClient: Review and Improvement Plan

A review of CoveClient v0.2.0: bugs, security concerns, and quality-of-life improvements.

Server-side items (including the full Lighthouse onboarding analysis and the CLI redesign) are in Cove's `IMPROVEMENTS.md`. IDs from that file (`SEC-n`, `BUG-n`, `QOL-n`) are referenced here where relevant.

> Nothing here has been implemented. This is a planning document. Unfamiliar terms are explained in the [Glossary](#9-glossary).

---

## Contents

1. [How to read this](#1-how-to-read-this)
2. [Backwards-compatibility rules](#2-backwards-compatibility-rules)
3. [Summary tables](#3-summary-tables)
4. [Focus: Lighthouse onboarding (client side)](#4-focus-lighthouse-onboarding-client-side)
5. [Details: security concerns](#5-details-security-concerns)
6. [Details: bugs](#6-details-bugs)
7. [Details: quality-of-life improvements](#7-details-quality-of-life-improvements)
8. [Suggested order of work](#8-suggested-order-of-work)
9. [Glossary](#9-glossary)

---

## 1. How to read this

Items are sorted by criticality, then by how much they improve things.

| Column | Scale |
|---|---|
| **Criticality** | **Critical**: data loss or compromise likely. **High**: wrong results or real risk under normal use. **Medium**: breaks in specific situations. **Low**: minor or cosmetic. |
| **Effort** | **S**: under 2 hours. **M**: half a day to a day. **L**: 2–3 days. **XL**: a week or more. |
| **Improvement** | How much better things get once it's done: **High / Medium / Low**. |
| **Compat** | **Safe**: existing callers are unaffected. **Opt-in**: only applies when used. **Care**: read the details first. |

---

## 2. Backwards-compatibility rules

Every project imports `v0.2.0`, so every proposal follows these rules:

1. **Existing functions keep their exact signatures.** New behavior comes through *new* functions, or optional extra arguments at the end of `New`. For example, `New(url, secret, platform)` keeps compiling when `New` gains optional settings, because Go lets callers leave those out.
2. **Error messages keep their current wording** (`coveClient: <Method>: Unexpected Status N`). Extra detail is only *added to the end*, so any project that checks for that text still works.
3. **Defaults only get safer.** For example, a default timeout only affects requests that would otherwise have hung forever.
4. **New features ship as a new version (`v0.3.0`).** Your projects stay on `v0.2.0` until you run `go get` in each one, whenever you like. `v0.2.0` keeps working because Cove promises not to change the `/v0` API.

---

## 3. Summary tables

### Security concerns

| ID | Issue | Criticality | Effort | Improvement | Compat |
|---|---|---|---|---|---|
| [CS-1](#cs-1-real-looking-token-hard-coded-in-mainmaingo) | Real-looking token hard-coded in `main/main.go` | Medium | S | Medium | Safe |
| [CS-2](#cs-2-token-sent-over-plain-http-with-no-warning) | Token sent over plain HTTP with no warning | Low | S | Low | Safe |
| [CS-3](#cs-3-bootstrap-leaves-token-storage-to-each-caller) | `Bootstrap()` leaves token storage to each caller | Low | (CQ-4) | Medium | Safe |

### Bugs

| ID | Issue | Criticality | Effort | Improvement | Compat |
|---|---|---|---|---|---|
| [CB-1](#cb-1-keys-arent-escaped-so-wrong-or-empty-secrets-are-returned-silently) | Keys aren't escaped, so the **wrong or empty secret is returned with no error** | **High** | S | High | Safe |
| [CB-2](#cb-2-no-timeout-so-calls-can-hang-forever) | No timeout, so calls can hang forever | Medium | S | High | Safe |
| [CB-3](#cb-3-cove-error-details-are-thrown-away) | Cove's error type/message is thrown away | Medium | S | High | Safe |
| [CB-4](#cb-4-trailing-slash-in-baseurl-breaks-writes) | Trailing slash in `baseURL` turns writes into reads | Medium | S | Medium | Safe |
| [CB-5](#cb-5-response-key-isnt-checked) | Response key isn't checked against the requested key | Low | S | Medium | Safe |
| [CB-6](#cb-6-empty-platformname-fails-silently-later) | Empty `platformName` fails later with confusing 400s | Low | S | Low | Safe |
| [CB-7](#cb-7-inconsistent-error-prefixes) | Inconsistent error prefixes | Low | S | Low | Safe |
| [CB-8](#cb-8-test-restores-global-transport-incorrectly) | Test restores the global transport incorrectly | Low | S | Low | Safe |

### Quality-of-life improvements

| ID | Improvement | Criticality | Effort | Improvement | Compat |
|---|---|---|---|---|---|
| [CQ-1](#cq-1-options-on-new-custom-httpclient-timeout) | Options on `New` (custom `http.Client`, timeout) | Medium | S | **High** | Safe |
| [CQ-2](#cq-2-typed-errors) | Typed errors (`errors.Is(err, ErrNotFound)`) | Medium | M | **High** | Safe |
| [CQ-3](#cq-3-context-aware-methods) | Context-aware methods (`GetSecretContext(ctx, ...)`) | Medium | M | **High** | Safe |
| [CQ-4](#cq-4-loadorbootstrap-helper) | `LoadOrBootstrap(path)` helper for Lighthouse-style onboarding | Medium | S | **High** | Safe |
| [CQ-5](#cq-5-multi-secret-helpers) | Multi-secret helpers (`GetSecrets(keys...)`, `MustGetSecret`) | Low | S | Medium | Safe |
| [CQ-6](#cq-6-waitforhealthy) | `WaitForHealthy(ctx)` / `WaitForReady(ctx)` | Low | S | Medium | Safe |
| [CQ-7](#cq-7-godoc-comments-and-examples) | GoDoc comments and runnable examples | Low | S | Medium | Safe |
| [CQ-8](#cq-8-exported-validatekey) | Exported `ValidateKey` | Low | S | Medium | Safe |
| [CQ-9](#cq-9-getsecretentry-with-version) | `GetSecretEntry` returning key, value, and version | Low | S | Low | Safe |
| [CQ-10](#cq-10-ci) | CI (vet, test, race) | Low | S | Low | Safe |
| [CQ-11](#cq-11-opt-in-retries) | Opt-in retries for network errors | Low | M | Low | Opt-in |

---

## 4. Focus: Lighthouse onboarding (client side)

Cove's `IMPROVEMENTS.md` §4 has the full story. This section covers only the CoveClient side.

### What's fragile on the client side

- **`Bootstrap()` hands you the token, and saving it is up to you.** If Lighthouse crashes between receiving the token and saving it, Cove has already locked the endpoint, so Lighthouse can't ask again.
- **A locked endpoint just says `Unexpected Status 403`.** Nothing tells you *what to do* about it.
- **No timeout (CB-2).** If Cove is slow to start, Lighthouse can hang forever.
- **`Health()` says "healthy" even when Cove's database is down** (Cove BUG-3), so "wait until Cove is up" can pass too early.

### What to add (all new functions; nothing existing changes)

1. **`LoadOrBootstrap(path)` (CQ-4).** One call that does the whole thing safely:
   - If the token file at `path` exists, read it. Done. No network call.
   - Otherwise, call bootstrap and **save the token to the file right away**. The write goes to a temporary file first and is then renamed, so you never end up with a half-written file, and it's readable only by its owner. Then check the token works, and return it.
   - If Cove says "locked", return an error that says what to do: *"run `cove bootstrap open` on the Cove host"*.

   It's safe to call on every start. If anything crashes, the next start just picks up where it left off.
2. **`WaitForReady(ctx)` (CQ-6).** Keeps checking until Cove is up and its database is reachable. Uses Cove's new `/v0/ready` if it's there, and falls back to `/v0/health`.
3. **Typed errors (CQ-2).** Lighthouse can check `errors.Is(err, coveclient.ErrBootstrapLocked)` instead of searching error text.

Combined with Cove's auto-closing bootstrap window (Cove QOL-3), onboarding becomes: run `cove bootstrap open 10m`, start Lighthouse, and `LoadOrBootstrap` handles the rest, including retrying after a crash.

---

## 5. Details: security concerns

Every item follows the same layout: **what's happening**, **why it matters**, **the fix**, and **will it break anything?**

### CS-1: Real-looking token hard-coded in `main/main.go`

**What's happening.** The scratch program `main/main.go` contains a 32-character token written directly in the code. That's the exact format Cove generates for its master token. The folder is in `.gitignore`, so it isn't in the repo.

**Why it matters.** It's still a plain-text copy of (possibly) the key to every secret, sitting on disk. It could end up in a backup, a zip you share, or a commit if `.gitignore` ever changes.

**The fix.** If it's your real token, change it in Cove, then update your projects. Replace the scratch program with `examples/basic/main.go`, which reads the URL and token from environment variables (CQ-7).

**Will it break anything?** Changing the token means updating every project that uses it. Per-project tokens (Cove SEC-4) would make this much easier in future.

### CS-2: Token sent over plain HTTP with no warning

**What's happening.** The client sends the master token to whatever URL it's given, even plain `http://` addresses on other machines, where it travels unencrypted.

**Why it matters.** Inside Docker (`http://cove:2100`) that's fine, because traffic never leaves the server. Across your LAN or the internet, anyone watching the traffic could read the token (see Cove SEC-3).

**The fix.** Log a one-time warning when the URL is `http://` and points at another machine. Optionally add a `WithRequireTLS()` option that refuses to send the token over plain HTTP.

**Will it break anything?** No. It's only a warning, and the stricter option is off unless you turn it on.

### CS-3: `Bootstrap()` leaves token storage to each caller

**What's happening.** After `Bootstrap()` returns the token, every project has to write its own "save this safely" code.

**Why it matters.** That code is easy to get wrong: a file other users can read, a half-written file after a crash, or the token printed to a log by accident.

**The fix.** CQ-4 (`LoadOrBootstrap`) does it once, correctly, for everyone.

**Will it break anything?** No.

---

## 6. Details: bugs

### CB-1: Keys aren't escaped, so wrong or empty secrets are returned silently

**Background.** Some characters have special meaning in a URL:
- `?` starts the "query" part (`/page?search=x`), which isn't part of the path.
- `#` starts a "fragment", which the client **never sends** to the server.
- `../` means "go up one folder".

**What's happening.** The client builds the URL by pasting the key straight in: `"/v0/secrets/" + id`. So if the key contains one of those characters, the URL means something other than you intended. **Tested against a test server:**

| You call | What's actually requested | You get back |
|---|---|---|
| `GetSecret("foo?x=1")` | `/v0/secrets/foo` (the rest becomes a query) | **`foo`'s value**, no error |
| `GetSecret("foo#bar")` | `/v0/secrets/foo` (the `#bar` is dropped) | **`foo`'s value**, no error |
| `GetSecret("../auth")` | `/v0/auth` (Cove redirects, the client follows) | **`""` (empty), no error** |
| `DeleteSecret("foo?x")` | `DELETE /v0/secrets/foo` | **deletes `foo`** |

**Why it matters.** You get the wrong secret, or an empty one, and **no error**. Your keys are fixed names in your code today, so it's unlikely, but if it ever happens it's silent and confusing.

**The fix.** Before sending, check the key with the same rules Cove uses (letters, numbers, `-`, `_`, `.`, up to 256 characters) and return a clear error if it doesn't match (CQ-8). As a second safeguard, escape the key (`url.PathEscape`) so special characters can't change the URL.

**Will it break anything?** No. Every valid key behaves exactly as before.

### CB-2: No timeout, so calls can hang forever

**What's happening.** Every request uses Go's shared default HTTP client, which has **no time limit**.

**Why it matters.** If Cove accepts the connection but never answers (for example, it's stuck waiting on its database, or halfway through shutting down), your project just waits. Usually at startup, with no error and no log line, so it looks frozen. The only workaround today is `http.DefaultClient.Timeout = ...`, which changes the limit for **every** HTTP call in your whole program, not just Cove's.

**The fix.** Give the client its own HTTP client with a default 15-second limit, adjustable through an option (CQ-1).

**Will it break anything?** No. A Cove request normally takes milliseconds, and anything past 15 seconds was already broken. The only difference is you get an error instead of a freeze.

### CB-3: Cove error details are thrown away

**What's happening.** When something fails, Cove sends back a helpful explanation, for example:
```json
{"error": {"type": "invalid_key", "message": "key contains invalid character ':'"}}
```
The client checks the status number *first*, and if it isn't the expected one, returns immediately **without reading that explanation**. So all you see is `coveClient: AddSecret: Unexpected Status 400`.

**Why it matters.** You have to guess *why* it failed, and often end up reading Cove's logs or code to find out.

**The fix.** When the status is wrong, read Cove's explanation and **add it to the end** of the error:
`coveClient: AddSecret: Unexpected Status 400: invalid_key: key contains invalid character ':'`

**Will it break anything?** No. The original text stays at the start, so code that checks for `"Unexpected Status 400"` still matches.

### CB-4: Trailing slash in `baseURL` breaks writes

**What's happening.** If you write the Cove URL with a slash at the end, `New("http://cove:2100/", ...)`, the client builds `http://cove:2100//v0/...` (two slashes). Cove answers "that page moved, go here instead" (a `301` redirect) to the one-slash version. Go's HTTP client follows the redirect but, following old web rules, **turns POST, PATCH, and DELETE into a plain GET and drops the body**.

**Tested:** `AddSecret("k", "v")` with a trailing slash ends up sending `GET /v0/secrets/k`. So instead of *creating* the secret, it *reads* it (adding a pull and a read event in Cove), and then reports the confusing error `Unexpected Status 200`.

**Why it matters.** A tiny typo in a config value makes writes misbehave in a way that's very hard to figure out.

**The fix.** Strip trailing slashes from the URL in `New`. Also consider telling the client not to follow redirects at all, since Cove never redirects on purpose.

**Will it break anything?** No.

### CB-5: Response key isn't checked

**What's happening.** When `GetSecret("A")` gets a reply, the client returns the value without checking that the reply is actually about key `A`.

**Why it matters.** If anything ever routes the request wrongly (CB-1, a proxy, a future Cove change), you silently get another secret's value, or an empty string.

**The fix.** If the key in the reply doesn't match the one you asked for, return an error. A few lines.

**Will it break anything?** No.

### CB-6: Empty `platformName` fails silently later

**What's happening.** `New(url, token, "")` is accepted. But every secret request then sends an empty `X-Cove-Source`, which Cove rejects with `400`. Because of CB-3, you don't see the reason.

**Why it matters.** A missing setting becomes a mystery "400" on every call.

**The fix.** If the platform name is empty, fill it in automatically with the program's own name (e.g. `lighthouse`). The signature of `New` stays the same.

**Will it break anything?** No. Calls that fail today would start working.

### CB-7: Inconsistent error prefixes

**What's happening.** `GetSecret` and `GetAllSecrets` say `coveClient: Unexpected Status N`. All the other methods include their name: `coveClient: DeleteSecret: Unexpected Status N`.

**Why it matters.** Without the method name, it's harder to tell from a log line which call failed.

**The fix.** Add the method name to those two.

**Will it break anything?** No. The `Unexpected Status N` part is unchanged.

### CB-8: Test restores global transport incorrectly

**What's happening.** One test (`TestHTTPDoError_Propagates`) swaps out a global piece of Go's HTTP setup to simulate a network failure, then puts back a slightly *different* value than the one that was there.

**Why it matters.** Right now it causes no problems. But it changes shared global state, and it would cause flaky failures if tests ever ran in parallel.

**The fix.** Once the client has its own HTTP client (CQ-1), tests can give it a fake one instead of touching globals.

**Will it break anything?** No. Test-only.

---

## 7. Details: quality-of-life improvements

### CQ-1: Options on `New` (custom `http.Client`, timeout)

**What it is.** Let `New` accept optional settings after the three current arguments:
```go
c := coveclient.New(url, token, "myapp")                                       // still works
c := coveclient.New(url, token, "myapp", coveclient.WithTimeout(5*time.Second)) // new
c := coveclient.New(url, token, "myapp", coveclient.WithHTTPClient(myClient))   // new
```
In Go, a trailing `opts ...Option` parameter can be left out entirely, so existing calls compile unchanged.

**Why it's worth it.** It fixes CB-2 (timeouts), lets projects use their own HTTP setup (proxies, custom certificates), and makes testing cleaner (CB-8).

**Breaks anything?** No.

### CQ-2: Typed errors

**What it is.** Named errors you can check for, instead of searching error text:
```go
value, err := c.GetSecret("MYAPP_DB_URL")
if errors.Is(err, coveclient.ErrNotFound) {
    // secret doesn't exist: create it, or fail with a clear message
}
```
Planned errors: `ErrNotFound`, `ErrAlreadyExists`, `ErrUnauthorized`, `ErrBootstrapLocked`, `ErrInvalidKey`. There would also be an `APIError` type holding the status code and Cove's explanation, for when you want the details.

**Why it's worth it.** Your projects can handle specific failures properly. For example, "secret missing" can be treated differently from "Cove is down".

**Breaks anything?** No. Error messages keep their current text. `ErrAlreadyExists` only starts working once Cove returns `409` for duplicates (Cove BUG-6). Until then, a duplicate is still a `500`.

### CQ-3: Context-aware methods

**What it is.** A second version of each method that takes a **context**, Go's standard way of saying "give up after X seconds" or "stop, we're shutting down":
```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
value, err := c.GetSecretContext(ctx, "MYAPP_DB_URL")
```
The existing methods stay and simply call the new ones with no deadline.

**Why it's worth it.** Projects can give each call its own time limit, and cancel waiting calls when they shut down.

**Breaks anything?** No. New methods only.

### CQ-4: `LoadOrBootstrap` helper

**What it is.** See §4: one call that loads a saved token, or bootstraps and saves one safely.

**Why it's worth it.** It removes the fragile part of Lighthouse onboarding, and any future project can reuse it.

**Breaks anything?** No.

### CQ-5: Multi-secret helpers

**What it is.**
```go
secrets, err := c.GetSecrets("MYAPP_DB_URL", "MYAPP_API_KEY", "MYAPP_SMTP_PASS")
// err lists *every* missing key at once, not just the first

dbURL := c.MustGetSecret("MYAPP_DB_URL") // crashes with a clear message if missing; for startup code
```

**Why it's worth it.** Almost every project loads a handful of secrets at startup and should stop if any are missing. This turns about ten lines of repeated code into one. When Cove adds batch fetch (Cove QOL-8), `GetSecrets` can switch to a single request without any change for callers.

**Breaks anything?** No.

### CQ-6: `WaitForHealthy`

**What it is.** `WaitForReady(ctx)` keeps checking, a little less often each time, until Cove is up and (once Cove BUG-3 is fixed) its database is reachable.

**Why it's worth it.** When a project and Cove start together in Docker, the project often starts first. Today each project needs its own retry loop.

**Breaks anything?** No.

### CQ-7: GoDoc comments and examples

**What it is.** Add Go doc comments (the `// GetSecret returns...` lines above each function) and an `example_test.go` with runnable examples. Replace the gitignored `main/` with a committed `examples/basic/` that reads its settings from the environment.

**Why it's worth it.** Your editor's hover help and pkg.go.dev currently show nothing for any method. Comments can also warn about side effects, e.g. "each `GetSecret` call counts as a pull and is logged by Cove".

**Breaks anything?** No.

### CQ-8: Exported `ValidateKey`

**What it is.** `coveclient.ValidateKey(key) error` checks a key name using Cove's rules. The client uses it internally (CB-1), and your projects can use it too.

**Why it's worth it.** You can check key names in a unit test and catch typos before deploying.

**Breaks anything?** No.

### CQ-9: `GetSecretEntry` with version

**What it is.** Cove already sends each secret's version number, but `GetSecret` throws it away. `GetSecretEntry(key)` would return the key, value, *and* version.

**Why it's worth it.** A project can tell when a secret has changed, for example to reload its config without restarting.

**Breaks anything?** No.

### CQ-10: CI

**What it is.** A GitHub Action that runs `go vet` and the tests (including Go's race detector) on every push, on both Go 1.21 (the oldest version `go.mod` allows) and the latest Go.

**Why it's worth it.** It automatically checks the "nothing breaks for existing projects" promise every time you change something.

**Breaks anything?** No.

### CQ-11: Opt-in retries

**What it is.** A `WithRetries(3)` option that automatically retries **reads only** when there's a network hiccup or Cove returns a server error, waiting a little longer each time.

**Why it's worth it.** It smooths over brief blips, such as Cove restarting while a project starts. Writes are never retried automatically: retrying a create could hit "already exists", and a retried update could apply twice.

**Breaks anything?** No. It's off unless you turn it on.

---

## 8. Suggested order of work

**Phase 0: today**
- CS-1: if the token in `main/main.go` is real, change it, and switch the scratch program to read it from an environment variable.

**Phase 1: v0.2.1, fixes only (about half a day)**
CB-1, CB-4, CB-5, CB-6, CB-7. No new functions. Safe to update every project to this version, but you don't have to.

**Phase 2: v0.3.0, new features (1–2 days)**
CQ-1 (fixes CB-2), CB-3 plus CQ-2, CQ-3, CQ-8, CQ-7, CB-8, CQ-10.

**Phase 3: onboarding (together with Cove Phase 3)**
CQ-4, CQ-6, and CS-2's optional warning.

**Phase 4: when Cove adds the matching server features**
CQ-5 with batch fetch (Cove QOL-8), CQ-9, CQ-11. Per-project tokens (Cove SEC-4) need **no** client change: a project just gets a different token.

---

## 9. Glossary

| Term | Plain meaning |
|---|---|
| **Token / bearer token** | A long password sent with each request (`Authorization: Bearer <token>`) to prove the caller is allowed in. |
| **Bootstrap** | The one-time handout of Cove's token to a new client that has no credentials yet. |
| **Escaping (URLs)** | Turning special characters like `?` or `#` into safe codes (`%3F`, `%23`) so they're treated as plain text, not URL syntax. |
| **Redirect (301)** | A server's "this moved, go over there" reply. Go's HTTP client follows it automatically. |
| **Timeout** | The maximum time to wait for an answer before giving up with an error. |
| **Context (Go)** | Go's standard way to pass "give up after X seconds" or "stop, we're shutting down" into a function. |
| **Typed / sentinel errors** | Named error values (like `ErrNotFound`) you can check with `errors.Is`, instead of reading error text. |
| **Variadic options** | Optional extra arguments at the end of a function (`opts ...Option`). Callers can leave them out entirely. |
| **Atomic write** | Writing to a temporary file and then renaming it, so the real file is either the old version or the complete new one, never half-written. |
| **Idempotent** | Safe to repeat: doing it twice has the same result as doing it once. |
| **Additive / backwards-compatible** | Adds something new without changing what already exists, so current users aren't affected. |
