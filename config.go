// Package bedrock is the official System Locker Bedrock client for Go.
//
// Bedrock targets software distributed to untrusted machines: every server
// response is Ed25519-signed and verified against a pinned public key before
// parsing, sessions rotate tokens on every heartbeat, and each request
// carries a fresh cryptographic challenge.
package bedrock

import "time"

// Config configures a Bedrock Client. Start from DefaultConfig, fill in
// SystemID and SigningPublicKey, and adjust the rest as needed.
type Config struct {
	// SystemID is the 20-character alphanumeric system identifier from the
	// developer dashboard. Required.
	SystemID string

	// Version is the client version reported to the server. The special
	// value "bypass" (the default) skips the server-side version gate.
	Version string

	// HWID is the device identifier reported to the server. An empty value
	// (the default) derives a stable hardware ID. Supply a custom value, or
	// use "1" to explicitly disable device locking.
	HWID string

	// HWIDMode selects how the device identifier is derived when HWID is
	// empty. The default since 1.0.0 is "sl-hwid": the SL-HWID
	// fault-tolerant threshold module (opt out with "legacy"
	// to restore the pre-1.0 hardware-factor hash). An explicit HWID always
	// takes precedence over either mode.
	HWIDMode string

	// SLHwidStore optionally redirects the secret-sharing module's
	// storage to a directory (files on every platform). Empty uses the
	// platform default (the registry on Windows, an application-support
	// directory elsewhere).
	SLHwidStore string

	// SLHwidExtraMandatory names additional hard-locked slots beyond
	// the module's own persisted value (for example "machine_guid").
	SLHwidExtraMandatory []string

	// BeatRate is the heartbeat interval. Default 30s; allowed 25s–3600s.
	BeatRate time.Duration

	// RequestTimeout bounds each HTTP request. Default 15s.
	RequestTimeout time.Duration

	// MaxServerClockSkew bounds how far server_time may drift from the
	// local clock before a response is rejected. Default 120s.
	MaxServerClockSkew time.Duration

	// BaseURL is the System Locker API root. Default
	// https://systemlocker.net. HTTPS is enforced.
	BaseURL string

	// InvisibleFolderBaseURL is the Invisible Folder root. Default
	// https://invisiblefolder.net. HTTPS is enforced.
	InvisibleFolderBaseURL string

	// UserAgent identifies the client to the server.
	UserAgent string

	// ProgramDigest, when set, is checked against the system's expected
	// program digest.
	ProgramDigest string

	// SigningKeyID, when set, pins the expected server signing key through
	// the X-Bedrock-Key-Id header.
	SigningKeyID string

	// InvisibleFolderAPIKey is only required to read metadata for API
	// Available, Password Protected, and System Locker Simple files.
	InvisibleFolderAPIKey string

	// SigningPublicKey is the base64url-encoded raw 32-byte Ed25519 public
	// key downloaded through the developer dashboard. Required.
	SigningPublicKey string

	// AutomaticHeartbeats controls the background heartbeat loop. Disable
	// it to drive HeartbeatNow yourself (event-loop or embedded contexts).
	AutomaticHeartbeats bool
}

// DefaultConfig returns a Config with every default filled in. Set SystemID
// and SigningPublicKey on the result before constructing a Client.
func DefaultConfig() Config {
	return Config{
		Version:                "bypass",
		HWID:                   "",
		HWIDMode:               "sl-hwid",
		BeatRate:               30 * time.Second,
		RequestTimeout:         15 * time.Second,
		MaxServerClockSkew:     120 * time.Second,
		BaseURL:                "https://systemlocker.net",
		InvisibleFolderBaseURL: "https://invisiblefolder.net",
		UserAgent:              "systemlocker-bedrock-go/1.0.0",
		AutomaticHeartbeats:    true,
	}
}

func (c Config) clone() Config {
	cloned := c
	cloned.SLHwidExtraMandatory = append([]string(nil), c.SLHwidExtraMandatory...)
	return cloned
}
