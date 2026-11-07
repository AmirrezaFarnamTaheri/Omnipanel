// Package supervisoripc connects a non-root watchdog to a separately installed
// root-owned supervisor over an authenticated local Unix socket. It never
// executes arbitrary shell commands or opens remote network connections.
package supervisoripc

import (
	"context"
	"errors"
)

var ErrUnavailable = errors.New("root supervisor IPC is not implemented")

type Client struct{}

func New(_ string) (*Client, error) { return nil, ErrUnavailable }

func newClient(_ string, _ uint32) (*Client, error) { return nil, ErrUnavailable }

func (c *Client) RestoreLastKnownGood(_ context.Context, _ string) error {
	return ErrUnavailable
}

func (c *Client) ObserveLastKnownGood(_ context.Context, _ string) (bool, error) {
	return false, ErrUnavailable
}
