// Command omnipanel-watchdog runs independently of the polling node agent.
package main

import (
	"context"
	"errors"
	"time"
)

var errWatchdogEntrypointUnavailable = errors.New("independent watchdog entrypoint is not implemented")

type options struct {
	NodeID           string
	Epoch            string
	JournalPath      string
	SupervisorSocket string
	Interval         time.Duration
}

func (o options) validate() error { return errWatchdogEntrypointUnavailable }

func run(_ context.Context, _ options) error { return errWatchdogEntrypointUnavailable }

func main() {}
