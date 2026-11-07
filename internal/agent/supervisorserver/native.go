package supervisorserver

import (
	"context"
	"errors"
)

var ErrNativeBackendUnavailable = errors.New("root native rollback backend is not implemented")

// NativeConfig is provisioned locally by the root administrator, never over
// the watchdog's lower-trust IPC request.
type NativeConfig struct {
	GenerationDirectory string
	ActiveConfigPath string
	SingBoxBinary string
	SingBoxBinaryDigest string
	SystemctlBinary string
	SystemctlBinaryDigest string
	HealthAddress string
}

type NativeBackend struct{}

func NewNativeBackend(cfg NativeConfig, generations map[string]bool) (*NativeBackend, error) {
	return nil, ErrNativeBackendUnavailable
}

func newNativeBackend(cfg NativeConfig, generations map[string]bool, trustedUID uint32) (*NativeBackend, error) {
	return nil, ErrNativeBackendUnavailable
}

func (b *NativeBackend) RestoreKnownGood(ctx context.Context, ref string) error {
	return ErrNativeBackendUnavailable
}

func (b *NativeBackend) ObserveKnownGood(ctx context.Context, ref string) (bool, error) {
	return false, ErrNativeBackendUnavailable
}
