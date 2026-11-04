// Package state records verified desired-state intent in a node-local journal.
// The initial test seam intentionally fails until SQLite WAL persistence exists.
package state

import (
	"context"
	"errors"

	"github.com/AmirrezaFarnamTaheri/Omnipanel/internal/manifest"
)

type Stage string

const (
	Received Stage = "RECEIVED"
	Verified Stage = "VERIFIED"
)

type Snapshot struct {
	Epoch              string
	StructuralSequence uint64
	MembershipSequence uint64
	Digest             string
	Stage              Stage
}

type Store struct{}

var errNotImplemented = errors.New("node journal not implemented")

func Open(string, string, string) (*Store, error) {
	return nil, errNotImplemented
}

func (*Store) Close() error { return nil }

func (*Store) RecordReceived(context.Context, manifest.Verified) (bool, error) {
	return false, errNotImplemented
}

func (*Store) Transition(context.Context, uint64, string, Stage) error {
	return errNotImplemented
}

func (*Store) Pending(context.Context) ([]Snapshot, error) {
	return nil, errNotImplemented
}

func (*Store) Cursor(context.Context) (manifest.Cursor, error) {
	return manifest.Cursor{}, errNotImplemented
}
