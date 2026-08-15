package bedrock

import (
	"context"
	"github.com/systemlocker/system-locker-bedrock-go/hwid"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	initPath = "/auth/bedrock/init"
	beatPath = "/auth/bedrock/beat"
)

// InitializationOptions tunes an authenticate call.
type InitializationOptions struct {
	// RequestInvisibleFolderToken asks the server for a short-lived
	// Invisible Folder token in the response.
	RequestInvisibleFolderToken bool

	// Variables names the server-side variables to fetch with the response.
	Variables []string
}

// HeartbeatOptions tunes a heartbeat.
type HeartbeatOptions struct {
	// RequestInvisibleFolderToken refreshes the Invisible Folder token.
	RequestInvisibleFolderToken bool
}

// AuthenticationResult is the outcome of an authenticate call: the verified
// response plus whether a live session was started.
type AuthenticationResult struct {
	Response       Response
	SessionStarted bool
}

// Client is a Bedrock client for one system. Construct with NewClient, call
// AuthenticateWithKey or AuthenticateWithPassword once, then let the
// background heartbeat keep the session alive (or drive HeartbeatNow
// manually with AutomaticHeartbeats disabled).
//
// A Client is safe for concurrent use.
type Client struct {
	config    Config
	http      HTTPClient
	invisible *InvisibleFolder

	mutex   sync.Mutex
	session *session
	hook    func(HeartbeatFailure)

	// now is swappable (validation uses a frozen clock).
	now func() time.Time
}

// Option customizes NewClient.
type Option func(*Client)

// WithHTTPClient injects a custom transport (tests, proxies, custom TLS
// stacks).
func WithHTTPClient(http HTTPClient) Option {
	return func(c *Client) { c.http = http }
}

// NewClient validates the configuration and returns a ready Client. The
// validation errors mirror the protocol specification exactly.
func NewClient(config Config, options ...Option) (*Client, error) {
	if config.HWID == "" {
		derived, err := hwid.DeviceHWID()
		if err != nil {
			return nil, fail(ErrConfiguration, "Could not derive the default hardware ID: %v. Supply a custom HWID or use \"1\" to disable device checks.", err)
		}
		config.HWID = derived
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	client := &Client{
		config: config.clone(),
		now:    time.Now,
	}
	for _, option := range options {
		option(client)
	}
	if client.http == nil {
		client.http = NewDefaultHTTPClient(config.RequestTimeout, config.UserAgent)
	}
	client.invisible = newInvisibleFolder(client)
	return client, nil
}

func validateConfig(config Config) error {
	if len(config.SystemID) != 20 || !isAlphanumeric(config.SystemID) {
		return fail(ErrConfiguration, "System ID must be exactly 20 alphanumeric characters.")
	}
	if config.BeatRate < 25*time.Second || config.BeatRate > 3600*time.Second {
		return fail(ErrConfiguration, "Bedrock heartbeat interval must be from 25 through 3600 seconds.")
	}
	if !strings.HasPrefix(config.BaseURL, "https://") {
		return fail(ErrConfiguration, "Bedrock base URL must use HTTPS.")
	}
	if config.MaxServerClockSkew <= 0 || config.MaxServerClockSkew > time.Hour {
		return fail(ErrConfiguration, "Bedrock clock-skew allowance must be greater than zero and no more than one hour.")
	}
	decoded, err := base64URLDecode(config.SigningPublicKey)
	if err != nil || len(decoded) != 32 {
		return fail(ErrConfiguration, "The Bedrock public key must decode to exactly 32 bytes.")
	}
	return nil
}

func isAlphanumeric(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		default:
			return false
		}
	}
	return true
}

// Config returns the (already validated) configuration.
func (c *Client) Config() Config { return c.config.clone() }

func (c *Client) transport() HTTPClient { return c.http }

// endpoint joins a base URL and a path, tolerating a trailing slash.
func (c *Client) endpoint(base, path string) string {
	if strings.HasSuffix(base, "/") {
		return base[:len(base)-1] + path
	}
	return base + path
}

// AuthenticateWithKey authenticates a license key and starts a session.
func (c *Client) AuthenticateWithKey(ctx context.Context, licenseKey string, options InitializationOptions) (AuthenticationResult, error) {
	return c.authenticate(ctx, url.Values{"key": {licenseKey}}, licenseKey, true, options)
}

// AuthenticateWithPassword authenticates an account and starts a session.
func (c *Client) AuthenticateWithPassword(ctx context.Context, username, password string, options InitializationOptions) (AuthenticationResult, error) {
	return c.authenticate(ctx, url.Values{"username": {username}, "password": {password}}, username, false, options)
}

func (c *Client) authenticate(ctx context.Context, fields url.Values, identity string, keyAuthentication bool, options InitializationOptions) (AuthenticationResult, error) {
	challenge, err := generateChallenge()
	if err != nil {
		return AuthenticationResult{}, err
	}

	fields.Set("system", c.config.SystemID)
	fields.Set("hwid", c.config.HWID)
	fields.Set("version", c.config.Version)
	fields.Set("beatrate", strconv.Itoa(int(c.config.BeatRate/time.Second)))
	fields.Set("challenge", challenge)
	if c.config.ProgramDigest != "" {
		fields.Set("digest", c.config.ProgramDigest)
	}
	if options.RequestInvisibleFolderToken {
		fields.Set("init-if", "true")
	}
	if len(options.Variables) > 0 {
		fields["variables[]"] = options.Variables
	}

	headers := c.signedHeaders()
	httpResponse := c.http.PostForm(ctx, c.endpoint(c.config.BaseURL, initPath), fields, headers)
	if !httpResponse.OK() {
		var message string
		if httpResponse.Err != nil {
			message = "Bedrock initialization transport failed: " + httpResponse.Err.Error()
		} else {
			message = "Bedrock initialization returned HTTP " + strconv.Itoa(httpResponse.StatusCode) + "."
		}
		return AuthenticationResult{}, fail(ErrTransport, "%s", message)
	}

	response, verifyErr := VerifySignedResponse(c.config, httpResponse, challenge, c.now())
	if verifyErr != nil {
		return AuthenticationResult{}, asError(verifyErr)
	}

	authenticatedCode := response.Code == CodeOK || response.Code == CodeOutdated
	if response.Authed != authenticatedCode {
		return AuthenticationResult{}, fail(ErrInvalidPayload, "Bedrock authentication flags contradict the response code.")
	}

	result := AuthenticationResult{Response: response}
	if !response.Authed {
		if len(response.Variables) > 0 || response.InvisibleFolderToken != "" {
			return AuthenticationResult{}, fail(ErrInvalidPayload, "A rejected Bedrock initialization returned successful-only data.")
		}
		return result, nil
	}
	if response.SessionToken == "" {
		return AuthenticationResult{}, fail(ErrInvalidPayload, "Authenticated Bedrock response did not contain a session token.")
	}
	if !strings.HasPrefix(response.SessionToken, "BRK_") {
		return AuthenticationResult{}, fail(ErrInvalidPayload, "Bedrock initialization returned an invalid session token format.")
	}

	identityHash := sha256Hex(identity)
	responseHash := response.UsernameHash
	if keyAuthentication {
		responseHash = response.LicenseKeyHash
	}
	if responseHash != identityHash {
		return AuthenticationResult{}, fail(ErrInvalidPayload, "Bedrock response identity hash does not match the authentication request.")
	}

	c.mutex.Lock()
	previous := c.session
	c.mutex.Unlock()
	if previous != nil {
		previous.stop()
		previous.wait()
	}

	authenticationSession := newSession(c, response.SessionToken, c.hook)
	if c.config.AutomaticHeartbeats {
		authenticationSession.start()
	}
	c.mutex.Lock()
	c.session = authenticationSession
	c.mutex.Unlock()

	if response.InvisibleFolderToken != "" {
		c.invisible.setToken(response.InvisibleFolderToken)
	}
	result.SessionStarted = true
	return result, nil
}

func (c *Client) signedHeaders() map[string]string {
	if c.config.SigningKeyID == "" {
		return nil
	}
	return map[string]string{"X-Bedrock-Key-Id": c.config.SigningKeyID}
}

// HeartbeatNow performs one manual heartbeat. Requires a live session.
func (c *Client) HeartbeatNow(ctx context.Context, options HeartbeatOptions) (Response, error) {
	c.mutex.Lock()
	current := c.session
	c.mutex.Unlock()
	if current == nil {
		return Response{}, fail(ErrSessionTerminated, "No Bedrock session is active.")
	}
	response, err := current.heartbeat(ctx, options)
	if err == nil && response.Authed && response.InvisibleFolderToken != "" {
		c.invisible.setToken(response.InvisibleFolderToken)
	}
	return response, err
}

// OnHeartbeatFailure installs a hook fired once when the session first
// fails. Safe to call before or after authentication.
func (c *Client) OnHeartbeatFailure(hook func(HeartbeatFailure)) {
	c.mutex.Lock()
	c.hook = hook
	current := c.session
	c.mutex.Unlock()
	if current != nil {
		current.setHook(hook)
	}
}

// IsAuthenticated reports whether a session is established and alive.
func (c *Client) IsAuthenticated() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.session != nil && c.session.aliveValue()
}

// HeartbeatCount returns the number of successfully completed heartbeats.
func (c *Client) HeartbeatCount() uint64 {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.session == nil {
		return 0
	}
	return c.session.completed.Load()
}

// InvisibleFolder exposes the download sub-API for the authenticated
// session.
func (c *Client) InvisibleFolder() *InvisibleFolder { return c.invisible }

// Shutdown tears down any live session and clears held tokens. Idempotent.
func (c *Client) Shutdown() {
	c.mutex.Lock()
	previous := c.session
	c.session = nil
	c.mutex.Unlock()
	if previous != nil {
		previous.stop()
		previous.wait()
	}
	c.invisible.clearToken()
}
