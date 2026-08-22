package bedrock

// ResponseCode enumerates every Bedrock response code. Unrecognized codes are
// a protocol violation, never a pass-through.
type ResponseCode int

const (
	CodeUnknown ResponseCode = iota
	CodeOK
	CodeOutdated
	CodeMissingField
	CodeInvalidRequest
	CodeInvalidSystem
	CodeInvalidCredentials
	CodeGoogleSsoRequired
	CodeUserNotVerified
	CodeInvalidKey
	CodeKeyFrozen
	CodeHwidBanned
	CodeHwidMismatch
	CodeSpoofSuspected
	CodeSystemPaused
	CodePlanInactive
	CodeProductionAuthUnavailable
	CodeUserLimitReached
	CodeExpiredKey
	CodeProgramDigestMismatch
	CodeInvalidBeatRate
	CodeNoActiveSigningKey
	CodeInvalidSession
	CodeSessionTerminated
	CodeStaleSession
	CodeHeartbeatTooEarly
	CodeHeartbeatVarianceExceeded
	CodeSigningKeyRevoked
	CodeConcurrentHeartbeat
	CodeInternalError
)

var codeNames = map[ResponseCode]string{
	CodeOK:                        "OK",
	CodeOutdated:                  "OUTDATED",
	CodeMissingField:              "MISSING_FIELD",
	CodeInvalidRequest:            "INVALID_REQUEST",
	CodeInvalidSystem:             "INVALID_SYSTEM",
	CodeInvalidCredentials:        "INVALID_CREDENTIALS",
	CodeGoogleSsoRequired:         "GOOGLE_SSO_REQUIRED",
	CodeUserNotVerified:           "USER_NOT_VERIFIED",
	CodeInvalidKey:                "INVALID_KEY",
	CodeKeyFrozen:                 "KEY_FROZEN",
	CodeHwidBanned:                "HWID_BANNED",
	CodeHwidMismatch:              "HWID_MISMATCH",
	CodeSpoofSuspected:            "SPOOF_SUSPECTED",
	CodeSystemPaused:              "SYSTEM_PAUSED",
	CodePlanInactive:              "PLAN_INACTIVE",
	CodeProductionAuthUnavailable: "PRODUCTION_AUTH_UNAVAILABLE",
	CodeUserLimitReached:          "USER_LIMIT_REACHED",
	CodeExpiredKey:                "EXPIRED_KEY",
	CodeProgramDigestMismatch:     "PROGRAM_DIGEST_MISMATCH",
	CodeInvalidBeatRate:           "INVALID_BEATRATE",
	CodeNoActiveSigningKey:        "NO_ACTIVE_SIGNING_KEY",
	CodeInvalidSession:            "INVALID_SESSION",
	CodeSessionTerminated:         "SESSION_TERMINATED",
	CodeStaleSession:              "STALE_SESSION",
	CodeHeartbeatTooEarly:         "HEARTBEAT_TOO_EARLY",
	CodeHeartbeatVarianceExceeded: "HEARTBEAT_VARIANCE_EXCEEDED",
	CodeSigningKeyRevoked:         "SIGNING_KEY_REVOKED",
	CodeConcurrentHeartbeat:       "CONCURRENT_HEARTBEAT",
	CodeInternalError:             "INTERNAL_ERROR",
}

var codeValues = func() map[string]ResponseCode {
	values := make(map[string]ResponseCode, len(codeNames))
	for code, name := range codeNames {
		values[name] = code
	}
	return values
}()

// ResponseCodeFromString maps a wire response code to its enumeration value,
// or CodeUnknown when the server sent something unrecognized.
func ResponseCodeFromString(value string) ResponseCode {
	if code, ok := codeValues[value]; ok {
		return code
	}
	return CodeUnknown
}

// String returns the wire name of the code ("UNKNOWN" when unset).
func (c ResponseCode) String() string {
	if name, ok := codeNames[c]; ok {
		return name
	}
	return "UNKNOWN"
}

// expectedAuthenticated reports whether a code must carry authed=true.
func expectedAuthenticated(code ResponseCode) bool {
	return code == CodeOK || code == CodeOutdated
}

// expectedFailure reports whether a code is a "failure" (malformed request or
// server-side configuration problem) rather than a credential "error".
func expectedFailure(code ResponseCode) bool {
	switch code {
	case CodeMissingField, CodeInvalidRequest, CodeInvalidSystem,
		CodeSystemPaused, CodePlanInactive, CodeProductionAuthUnavailable,
		CodeProgramDigestMismatch, CodeInvalidBeatRate,
		CodeNoActiveSigningKey, CodeInternalError:
		return true
	default:
		return false
	}
}

func expectedError(code ResponseCode) bool {
	return code != CodeOK && !expectedFailure(code)
}

// Variable is a single server-side variable value. The server reports a
// requested-but-absent variable as JSON false; Found distinguishes that from
// an empty string value.
type Variable struct {
	Value string
	Found bool
}

// Response is a fully verified Bedrock response payload.
type Response struct {
	Code             ResponseCode
	ResponseCodeName string
	HumanResponse    string
	IsError          bool
	IsFailure        bool
	Authed           bool
	ProtocolVersion  string
	// KeyID is the signing-key ULID authenticated inside the response payload.
	KeyID                string
	System               string
	Challenge            string
	ServerTime           int64
	HumanTime            string
	SessionToken         string // empty when absent
	LicenseKeyHash       string // empty when absent
	UsernameHash         string // empty when absent
	TerminationMessage   string // empty when absent
	SsoURL               string // Google SSO portal URL, on GOOGLE_SSO_REQUIRED denials
	InvisibleFolderToken string // empty when absent

	// Variables holds the requested server-side variables, by name.
	Variables map[string]Variable
}
