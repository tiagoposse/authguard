package entauth

import "fmt"

// GuardError represents an authorization failure with an HTTP status code.
type GuardError struct {
	Code    int
	Message string
}

func (e *GuardError) Error() string {
	return e.Message
}

// NewGuardError creates a new GuardError.
func NewGuardError(code int, message string) *GuardError {
	return &GuardError{Code: code, Message: message}
}

// Errorf creates a GuardError with a formatted message.
func Errorf(code int, format string, args ...interface{}) *GuardError {
	return &GuardError{Code: code, Message: fmt.Sprintf(format, args...)}
}

var (
	ErrNotAuthenticated  = NewGuardError(401, "authentication required")
	ErrNotAdmin          = NewGuardError(403, "admin access required")
	ErrElevationRequired = NewGuardError(403, "admin elevation required")
)
