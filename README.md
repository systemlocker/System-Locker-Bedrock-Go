# System Locker Bedrock — Go

Official Go client for **System Locker Bedrock**, the license-verification
protocol for software distributed to **untrusted machines**. Every server
response is Ed25519-signed and verified against a pinned public key before
parsing, sessions rotate tokens on every heartbeat, and each request carries
a fresh cryptographic challenge — replay attacks and forged responses are
infeasible even for an attacker who fully controls the network.

If your software runs on a machine you control, the simpler stateless client
may fit better (see the System Locker Simple libraries).

## Install

```sh
go get github.com/systemlocker/system-locker-bedrock-go
```

No third-party dependencies — standard library only.

## Quickstart

```go
package main

import (
    "context"
    "fmt"

    bedrock "github.com/systemlocker/system-locker-bedrock-go"
)

func main() {
    config := bedrock.DefaultConfig()
    config.SystemID = "abcdefghijklmnopqrst"                 // from the dashboard
    config.SigningPublicKey = "…base64url Ed25519 key…"      // from the dashboard
    config.Version = "1.0.0"

    client, _ := bedrock.NewClient(config)
    client.OnHeartbeatFailure(func(failure bedrock.HeartbeatFailure) {
        fmt.Println("session ended:", failure.Error.Message)
        // Save state and exit — the license is no longer verified as live.
    })

    result, err := client.AuthenticateWithKey(context.Background(), "SL-XXXX-XXXX-XXXX",
        bedrock.InitializationOptions{
            RequestInvisibleFolderToken: true,
            Variables:                   []string{"tier"},
        })
    if err != nil || !result.SessionStarted {
        return // rejected or tampered — treat exactly like a failed login
    }

    // …your protected application logic; heartbeats run automatically…
    defer client.Shutdown()
}
```

## What the client enforces for you

- **Signed responses only.** The Ed25519 signature is verified against the
  pinned key _before_ any parsing; tampered payloads never reach your code.
- **Challenge echoes.** Every init/beat carries a fresh 86-character CSPRNG
  challenge that the server must echo exactly.
- **Freshness.** `server_time` must be within `MaxServerClockSkew`
  (default 120 s) of the local clock.
- **Identity binding.** The response's `license_key_hash`/`username_hash`
  must equal the locally computed SHA-256 of the submitted credential.
- **Token rotation.** Init tokens start with `BRK_`, every heartbeat rotates
  to a `BRF_` token; a lost heartbeat response is retried once, idempotently.
- **Denial-only unsigned responses.** Exactly one unsigned response is ever
  accepted: a `SIGNING_KEY_REVOKED` termination, which only ends the session.

Errors carry a `Kind` (`bedrock.ErrInvalidSignature`,
`bedrock.ErrFreshnessViolation`, …) so you can distinguish infrastructure
problems (`ErrTransport`) from attacks (`ErrInvalidSignature`,
`ErrUnsignedResponse`) from legitimate denials (`ErrSessionTerminated`).

## Heartbeats

With `AutomaticHeartbeats: true` (the default) a background goroutine beats
every `BeatRate` (25–3600 s). When it fails, your `OnHeartbeatFailure` hook
fires once and the session is dead. Disable it and call
`client.HeartbeatNow(ctx, …)` yourself if you prefer manual control.

## Invisible Folder file delivery

```go
result, _ := client.InvisibleFolder().DownloadIfNew(ctx, "app-assets-v1", lastRevision, "assets.zip")
if result.Downloaded {
    lastRevision = result.Revision // persist this
}
```

`Download` (memory), `DownloadToFile` (disk, unencrypted), `Metadata`, and
`DownloadIfNew` (revision-checked) are available. Tokens are held in memory
only and cleared on `Shutdown`.

## Google SSO (account authentication)

Accounts created through Google sign-in have no local password on the
server. A `username`/`password` authentication for such an account is
answered with a signed `GOOGLE_SSO_REQUIRED` denial whose payload carries
`sso_url` — the portal where the user completes Google sign-in and receives
a system-specific password (valid 180 days) to use as their account
password. There is no callback; the user transcribes the generated password
into your login form and you simply retry.

```go
result, err := client.AuthenticateWithPassword(ctx, username, password)
if err == nil && result.Response.Code == bedrock.CodeGoogleSsoRequired {
    // The denial's URL is authoritative; open it in the default browser.
    portal := result.Response.SsoURL
    if portal == "" {
        portal = client.GoogleSsoURL()
    }
    if !bedrock.OpenURL(portal) {
        fmt.Println("Finish Google sign-in at:", portal) // headless fallback
    }
}
```

You can also start the flow before any denial: `client.BeginGoogleSso()`
(or `bedrock.BeginGoogleSso(systemID)`) opens the portal and returns the URL
plus whether a browser actually launched.

## Device identifiers (HWID)

The library derives a hardware ID by default; set `Config.HWID = "1"` only to
explicitly disable device locking.

```go
import "github.com/systemlocker/system-locker-bedrock-go/hwid"

device, err := hwid.DeviceHWID()
```

The `hwid` package derives a stable identifier from the machine GUID,
hardware UUID, CPU id, and MAC (Windows and Linux; factors degrade
gracefully, the machine GUID is required). Providing your own stable value
through `Config.HWID` is equally supported — and avoids hardware-enumeration
quirks entirely.

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately through the
System Locker support channels, not via public issues.
