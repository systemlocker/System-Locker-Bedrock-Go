package bedrock

import (
	"os/exec"
	"runtime"
)

// googleSsoPortal is the fixed entry point of the Google SSO flow. The
// server mints this URL in GOOGLE_SSO_REQUIRED denials; the client mirrors
// it so the flow can start before a denial is ever seen.
const googleSsoPortal = "https://systemlocker.net/user/sso?system="

// GoogleSsoURL returns the Google SSO portal URL for a system. After the
// user signs in there, the portal shows a system-specific password that is
// valid for 180 days and is then used as the account password.
func GoogleSsoURL(systemID string) string {
	return googleSsoPortal + escapeSystemID(systemID)
}

// escapeSystemID percent-encodes everything except unreserved characters,
// matching the server's rawurlencode so every client builds byte-identical
// portal URLs.
func escapeSystemID(value string) string {
	const hexDigits = "0123456789ABCDEF"
	var encoded []byte
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			encoded = append(encoded, c)
		default:
			encoded = append(encoded, '%', hexDigits[c>>4], hexDigits[c&0x0F])
		}
	}
	return string(encoded)
}

// OpenURL launches the default browser at rawURL. It reports whether the
// browser launched; hosts without one (servers, containers) return false
// and the caller falls back to displaying the URL.
func OpenURL(rawURL string) bool {
	if rawURL == "" {
		return false
	}
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL)
	case "darwin":
		command = exec.Command("open", rawURL)
	default:
		command = exec.Command("xdg-open", rawURL)
	}
	if err := command.Start(); err != nil {
		return false
	}
	// Reap the opener without blocking the caller on browser lifetime.
	go func() { _ = command.Wait() }()
	return true
}

// BeginGoogleSso opens the Google SSO portal for a system in the default
// browser. The URL is always returned so flows without a browser can hand
// it to the developer; opened reports whether the launch succeeded.
func BeginGoogleSso(systemID string) (portalURL string, opened bool) {
	portalURL = GoogleSsoURL(systemID)
	return portalURL, OpenURL(portalURL)
}

// GoogleSsoURL returns the portal URL for the client's configured system.
func (c *Client) GoogleSsoURL() string {
	return GoogleSsoURL(c.config.SystemID)
}

// BeginGoogleSso opens the Google SSO portal for the client's configured
// system. See the package-level function for the result contract.
func (c *Client) BeginGoogleSso() (string, bool) {
	return BeginGoogleSso(c.config.SystemID)
}
