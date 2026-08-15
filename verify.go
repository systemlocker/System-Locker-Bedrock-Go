package bedrock

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"
)

const (
	protocolVersion   = "bedrock-v1"
	signatureBytes    = 64
	publicKeyBytes    = 32
	challengeBytes    = 64
	maxTransportBytes = 1024 * 1024
)

// generateChallenge returns a fresh 64-byte base64url challenge from the
// system CSPRNG.
func generateChallenge() (string, error) {
	random := make([]byte, challengeBytes)
	if _, err := rand.Read(random); err != nil {
		return "", fail(ErrLocalFailure, "A cryptographically secure Bedrock challenge could not be generated.")
	}
	return base64.RawURLEncoding.EncodeToString(random), nil
}

// sha256Hex returns the lowercase-hex SHA-256 of value, used for identity
// hashes.
func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// base64URLDecode decodes an unpadded base64url value with the same
// strictness as every System Locker client: non-empty, at most 1 MiB, no
// length that cannot be base64, and base64url alphabet only.
func base64URLDecode(value string) ([]byte, error) {
	if value == "" || len(value) > maxTransportBytes || len(value)%4 == 1 {
		return nil, fail(ErrInvalidPayload, "Invalid base64url length.")
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return nil, fail(ErrInvalidPayload, "Invalid base64url character.")
		}
	}
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(value)))
	n, err := base64.RawURLEncoding.Decode(decoded, []byte(value))
	if err != nil {
		return nil, fail(ErrInvalidPayload, "Invalid base64url value.")
	}
	return decoded[:n], nil
}

// VerifySignedResponse implements the Bedrock verification pipeline in the
// exact order required by the protocol specification: transport headers,
// encoding, Ed25519 signature, then payload validation. It is exported so
// every official client runs the same conformance vectors against it.
func VerifySignedResponse(config Config, httpResponse HTTPResponse, expectedChallenge string, now time.Time) (Response, error) {
	if httpResponse.Header("x-bedrock-protocol") != protocolVersion || httpResponse.Header("x-bedrock-signed") == "false" {
		return Response{}, fail(ErrUnsignedResponse, "Bedrock response is missing its signed transport headers.")
	}

	signedBytes, err := base64URLDecode(string(httpResponse.Body))
	if err != nil || len(signedBytes) <= signatureBytes {
		return Response{}, fail(ErrInvalidPayload, "Bedrock signed response has an invalid encoding or length.")
	}

	publicKey, err := base64URLDecode(config.SigningPublicKey)
	if err != nil || len(publicKey) != publicKeyBytes {
		return Response{}, fail(ErrConfiguration, "Pinned Bedrock public key is not a raw 32-byte Ed25519 key.")
	}

	signature := signedBytes[:signatureBytes]
	message := signedBytes[signatureBytes:]
	if !ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) {
		return Response{}, fail(ErrInvalidSignature, "Bedrock response signature verification failed.")
	}

	response, err := parsePayload(config, string(message), expectedChallenge, now, true)
	if err != nil {
		return Response{}, err
	}
	if response.KeyID == "" || httpResponse.Header("x-bedrock-key-id") != response.KeyID {
		return Response{}, fail(ErrInvalidPayload, "Bedrock response signing key ID is missing or inconsistent.")
	}
	if config.SigningKeyID != "" && response.KeyID != config.SigningKeyID {
		return Response{}, fail(ErrInvalidPayload, "Bedrock response signing key ID does not match the configured pin.")
	}
	return response, nil
}

// ParseUnsignedRevocation handles the single permitted unsigned response: a
// SIGNING_KEY_REVOKED termination with a termination message. It is
// denial-only and never grants access.
func ParseUnsignedRevocation(config Config, httpResponse HTTPResponse, expectedChallenge string, now time.Time) (Response, error) {
	if httpResponse.Header("x-bedrock-signed") != "false" || httpResponse.Header("x-bedrock-protocol") != protocolVersion {
		return Response{}, fail(ErrUnsignedResponse, "Bedrock returned an unauthenticated response.")
	}
	parsed, err := parsePayload(config, string(httpResponse.Body), expectedChallenge, now, false)
	if err != nil {
		return Response{}, err
	}
	if parsed.Code != CodeSigningKeyRevoked || parsed.TerminationMessage == "" {
		return Response{}, fail(ErrUnsignedResponse, "Unsigned Bedrock response is diagnostic only and cannot be trusted.")
	}
	return parsed, nil
}

func parsePayload(config Config, jsonText string, expectedChallenge string, now time.Time, requireKeyID bool) (Response, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(jsonText), &raw); err != nil {
		return Response{}, fail(ErrInvalidPayload, "Bedrock response JSON is invalid: %v", err)
	}

	requireString := func(name string) (string, error) {
		value, ok := raw[name]
		if !ok {
			return "", &JSONError{Field: name}
		}
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return "", &JSONError{Field: name}
		}
		return text, nil
	}
	requireBool := func(name string) (bool, error) {
		value, ok := raw[name]
		if !ok {
			return false, &JSONError{Field: name}
		}
		var flag bool
		if err := json.Unmarshal(value, &flag); err != nil {
			return false, &JSONError{Field: name}
		}
		return flag, nil
	}
	optionalString := func(name string) (string, error) {
		value, ok := raw[name]
		if !ok || string(value) == "null" {
			return "", nil
		}
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return "", &JSONError{Field: name}
		}
		return text, nil
	}

	var response Response
	var err error
	if response.ProtocolVersion, err = requireString("protocol_version"); err != nil {
		return Response{}, payloadError(err)
	}
	if requireKeyID {
		if response.KeyID, err = requireString("kid"); err != nil {
			return Response{}, payloadError(err)
		}
	} else if response.KeyID, err = optionalString("kid"); err != nil {
		return Response{}, payloadError(err)
	}
	if response.System, err = requireString("system"); err != nil {
		return Response{}, payloadError(err)
	}
	if response.ResponseCodeName, err = requireString("response_code"); err != nil {
		return Response{}, payloadError(err)
	}
	response.Code = ResponseCodeFromString(response.ResponseCodeName)
	if response.HumanResponse, err = requireString("human_response"); err != nil {
		return Response{}, payloadError(err)
	}
	if response.IsError, err = requireBool("is_error"); err != nil {
		return Response{}, payloadError(err)
	}
	if response.IsFailure, err = requireBool("is_failure"); err != nil {
		return Response{}, payloadError(err)
	}
	if response.Authed, err = requireBool("authed"); err != nil {
		return Response{}, payloadError(err)
	}
	if response.HumanTime, err = requireString("human_time"); err != nil {
		return Response{}, payloadError(err)
	}
	if response.Challenge, err = requireString("challenge"); err != nil {
		return Response{}, payloadError(err)
	}

	serverTimeRaw, ok := raw["server_time"]
	if !ok {
		return Response{}, payloadError(&JSONError{Field: "server_time"})
	}
	serverTime, valid := parseJSONInteger(serverTimeRaw)
	if !valid {
		return Response{}, payloadError(&JSONError{Field: "server_time"})
	}
	response.ServerTime = serverTime

	if response.SessionToken, err = optionalString("session_token"); err != nil {
		return Response{}, payloadError(err)
	}
	if response.LicenseKeyHash, err = optionalString("license_key_hash"); err != nil {
		return Response{}, payloadError(err)
	}
	if response.UsernameHash, err = optionalString("username_hash"); err != nil {
		return Response{}, payloadError(err)
	}
	if response.TerminationMessage, err = optionalString("termination_message"); err != nil {
		return Response{}, payloadError(err)
	}
	if response.InvisibleFolderToken, err = optionalString("invisible_folder_token"); err != nil {
		return Response{}, payloadError(err)
	}

	if variablesRaw, ok := raw["variables"]; ok {
		variables, err := parseVariables(variablesRaw)
		if err != nil {
			return Response{}, payloadError(err)
		}
		response.Variables = variables
	}

	if response.ProtocolVersion != protocolVersion {
		return Response{}, fail(ErrInvalidPayload, "Unsupported Bedrock protocol version.")
	}
	if response.Code == CodeUnknown {
		return Response{}, fail(ErrInvalidPayload, "Bedrock response contains an unknown response code.")
	}
	if response.Authed != expectedAuthenticated(response.Code) ||
		response.IsError != expectedError(response.Code) ||
		response.IsFailure != expectedFailure(response.Code) {
		return Response{}, fail(ErrInvalidPayload, "Bedrock response flags contradict its response code.")
	}
	if response.System != config.SystemID {
		return Response{}, fail(ErrInvalidPayload, "Bedrock response is bound to a different system.")
	}
	if response.Challenge != expectedChallenge {
		return Response{}, fail(ErrInvalidPayload, "Bedrock response challenge does not match the request.")
	}
	difference := response.ServerTime - now.Unix()
	if difference < 0 {
		difference = -difference
	}
	if difference > int64(config.MaxServerClockSkew/time.Second) {
		return Response{}, fail(ErrFreshnessViolation, "Bedrock response server time is outside the configured freshness window.")
	}
	return response, nil
}

func payloadError(err error) error {
	if jsonErr, ok := err.(*JSONError); ok {
		return fail(ErrInvalidPayload, "%s", jsonErr.Error())
	}
	return fail(ErrInvalidPayload, "%s", err.Error())
}

// parseJSONInteger accepts a JSON number only when it is written as an exact
// integer literal (no exponent, no fraction).
func parseJSONInteger(raw json.RawMessage) (int64, bool) {
	n, err := strconv.ParseInt(string(raw), 10, 64)
	return n, err == nil
}

func parseVariables(raw json.RawMessage) (map[string]Variable, error) {
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fail(ErrInvalidPayload, "Bedrock field 'variables' has the wrong type.")
	}
	variables := make(map[string]Variable, len(entries))
	for name, value := range entries {
		var text string
		if err := json.Unmarshal(value, &text); err == nil {
			variables[name] = Variable{Value: text, Found: true}
			continue
		}
		var flag bool
		if err := json.Unmarshal(value, &flag); err == nil && !flag {
			variables[name] = Variable{Found: false}
			continue
		}
		return nil, fail(ErrInvalidPayload, "Bedrock variable has the wrong type.")
	}
	return variables, nil
}
