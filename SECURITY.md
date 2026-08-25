# Security Policy

## Threat model

Bedrock assumes the client machine is **untrusted**: an attacker can read
memory, intercept traffic, and replay captured messages. The controls that
matter therefore live in the protocol, not in obfuscation:

- Every response is Ed25519-signed and verified against the pinned
  `SigningPublicKey` **before parsing**. Nothing unsigned is ever trusted —
  with one denial-only exception (`SIGNING_KEY_REVOKED`), which can only end
  a session.
- Per-request 64-byte CSPRNG challenges must be echoed exactly, binding each
  response to one request and defeating replay.
- `server_time` freshness, system/identity echoes, and token rotation
  (`BRK_`/`BRF_`) are all verified on every response.
- All client randomness comes from `crypto/rand`.

## Accepted limitations

- Go strings and byte slices are garbage-collected; credentials cannot be
  wiped deterministically in memory the way the C++ client wipes them.
- Debugger-detection and code self-integrity checks from the C++ client do
  not meaningfully port to a managed runtime and are not implemented. The
  signature verification remains the real control.
- Downloads to disk are written unencrypted (parity with the C++ client);
  protect them at the application layer if needed.
- TLS certificate validation is always on; TLS public-key pinning is not
  implemented (the response signature already provides the
  man-in-the-middle defense).

## SL-HWID module

The default threshold HWID module makes copied state and casual spoofing
harder by requiring a stored enrollment plus enough current factors. Our
objective is to reduce HWID churn from minor hardware changes, without
reducing the strength of HWID as a locking mechanism. The key itself is never
persisted. The module wipes key material deterministically after use,
matching the rest of this client.

Applications using the same store share one enrollment and HWID. Protect that
store and choose a separate explicit store when isolation is required.

## Reporting a vulnerability

Report privately through the System Locker developer dashboard. Do not open
public issues for security problems.
