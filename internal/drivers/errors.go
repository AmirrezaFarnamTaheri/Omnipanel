package drivers

import (
	"errors"
	"fmt"
)

var ErrUnsupportedCapability = errors.New("unsupported capability")

// CapabilityError exposes only a known runtime/operation identity. Never pass
// configuration values, credentials or untrusted exception text into it.
type CapabilityError struct {
	Driver    string
	Operation string
}

func (e *CapabilityError) Error() string {
	return fmt.Sprintf("%s: %s: %s", e.Driver, e.Operation, ErrUnsupportedCapability)
}
func (e *CapabilityError) Unwrap() error { return ErrUnsupportedCapability }
