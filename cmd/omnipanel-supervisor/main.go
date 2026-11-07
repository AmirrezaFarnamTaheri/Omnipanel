// Command omnipanel-supervisor is the root-owned, fixed-command recovery
// endpoint for the separately running unprivileged node watchdog.
package main

import (
	"context"
	"errors"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/agent/supervisorserver"
)

var errRootProvisioningMissing = errors.New("root supervisor local provisioning not implemented")

type provisioning struct {
	SocketPath string
	WatchdogUID uint32
	WatchdogGID uint32
	AllowedGenerations []string
	Native supervisorserver.NativeConfig
}

func loadProvisioning(path string) (provisioning, error) {
	return provisioning{}, errRootProvisioningMissing
}

func loadProvisioningForTesting(path string, ownerUID uint32) (provisioning,error) {
	return provisioning{}, errRootProvisioningMissing
}

func run(ctx context.Context, cfg provisioning) error {
	return errRootProvisioningMissing
}

func main() {}
