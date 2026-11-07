package singbox

import (
	"context"
	"errors"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/drivers"
)

// NativeStager is an unprivileged, locally configured Sing-box preflight boundary.
// It cannot activate a listener, restart a service, or advance applied state.
type NativeStager struct{}

// StagedConfig confirms only a validated on-disk candidate, never a live apply.
type StagedConfig struct {
	ComponentID string
	SHA256      string
	Path        string
}

var ErrNativeUnavailable = errors.New("native Sing-box validation is not implemented")

func NewNativeStager(binaryPath, stagingDirectory string, build drivers.BuildIdentity) (*NativeStager, error) {
	return nil, ErrNativeUnavailable
}

func (n *NativeStager) Stage(ctx context.Context, artifact drivers.ConfigArtifact) (StagedConfig, error) {
	return StagedConfig{}, ErrNativeUnavailable
}
