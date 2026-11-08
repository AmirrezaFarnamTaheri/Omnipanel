package supervisorserver

import (
    "context"
)

// verifyProcessListener must prove that the fixed root-supervised systemd
// MainPID is running the pinned native executable and owns the exact
// loopback listening socket. This stub deliberately fails closed for TDD.
func verifyProcessListener(pid int, expectedBinaryDigest, healthAddress string) error {
    return ErrNativeFailed
}

// verifyLinuxUnitListener obtains the unit's MainPID using only a pinned
// systemctl executable and delegates to the kernel /proc identity witness.
// No arbitrary commands, paths, ports or process IDs come from IPC.
func verifyLinuxUnitListener(ctx context.Context, systemctlBinary, expectedBinaryDigest, healthAddress string) error {
    return ErrNativeFailed
}
