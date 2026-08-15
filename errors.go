package bedrock

import "fmt"

// ErrorKind categorizes every failure a Bedrock client can surface. The
// vocabulary is identical across all official System Locker libraries.
type ErrorKind uint8

const (
	// ErrConfiguration means the local configuration is invalid. No request
	// was sent.
	ErrConfiguration ErrorKind = iota
	// ErrTransport means the HTTP exchange itself failed or returned a
	// non-2xx status.
	ErrTransport
	// ErrUnsignedResponse means the response lacked its signed transport
	// headers and is not the one permitted unsigned revocation.
	ErrUnsignedResponse
	// ErrInvalidSignature means Ed25519 verification against the pinned
	// public key failed.
	ErrInvalidSignature
	// ErrInvalidPayload means the response was signed but its contents are
	// inconsistent with the protocol or this request.
	ErrInvalidPayload
	// ErrFreshnessViolation means server_time is outside the configured
	// clock-skew window.
	ErrFreshnessViolation
	// ErrSessionTerminated means the session ended, by the server or
	// locally.
	ErrSessionTerminated
	// ErrLocalFailure covers local runtime failures (I/O, CSPRNG, clock).
	ErrLocalFailure
)

func (k ErrorKind) String() string {
	switch k {
	case ErrConfiguration:
		return "Configuration"
	case ErrTransport:
		return "Transport"
	case ErrUnsignedResponse:
		return "UnsignedResponse"
	case ErrInvalidSignature:
		return "InvalidSignature"
	case ErrInvalidPayload:
		return "InvalidPayload"
	case ErrFreshnessViolation:
		return "FreshnessViolation"
	case ErrSessionTerminated:
		return "SessionTerminated"
	case ErrLocalFailure:
		return "LocalFailure"
	default:
		return "LocalFailure"
	}
}

// Error is the error type returned by every client operation.
type Error struct {
	Kind    ErrorKind
	Message string
}

func (e *Error) Error() string { return e.Message }

func fail(kind ErrorKind, format string, args ...any) *Error {
	return &Error{Kind: kind, Message: fmt.Sprintf(format, args...)}
}

// asError coerces a non-nil error into *Error, wrapping unknown errors as
// LocalFailure.
func asError(err error) *Error {
	if err == nil {
		return nil
	}
	if bedrockErr, ok := err.(*Error); ok {
		return bedrockErr
	}
	return &Error{Kind: ErrLocalFailure, Message: err.Error()}
}

// JSONError is the error produced when a payload field is missing or has the
// wrong type.
type JSONError struct {
	Field string
}

func (e *JSONError) Error() string {
	return "Bedrock field '" + e.Field + "' is missing or has the wrong type."
}

var _ error = (*JSONError)(nil)
var _ error = (*Error)(nil)
