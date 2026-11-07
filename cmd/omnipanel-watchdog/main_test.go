package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func validOptions(t *testing.T) options {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return options{
		NodeID: "62c478bb-47c3-4dc6-a363-a2fbde813810",
		Epoch: "ea2429da-7540-4e40-ae70-38fd3f19794b",
		JournalPath: filepath.Join(dir, "journal.sqlite"),
		SupervisorSocket: "/run/omnipanel/root-supervisor.sock",
		Interval: 250 * time.Millisecond,
	}
}

func TestWatchdogCLIValidatesLocalScopeAndFiniteRetryInterval(t *testing.T) {
	base := validOptions(t)
	if err := base.validate(); err != nil {
		t.Fatalf("valid nonsecret scope rejected: %v", err)
	}
	cases := []struct {
		name string
		change func(*options)
	}{
		{"empty node", func(o *options) { o.NodeID = "" }},
		{"wrong node", func(o *options) { o.NodeID = "../../node" }},
		{"empty epoch", func(o *options) { o.Epoch = "" }},
		{"wrong epoch", func(o *options) { o.Epoch = "other-epoch" }},
		{"relative journal", func(o *options) { o.JournalPath = "./journal.sqlite" }},
		{"journal path traversal", func(o *options) { o.JournalPath = "/tmp/../tmp/journal.sqlite" }},
		{"relative supervisor", func(o *options) { o.SupervisorSocket = "../root.sock" }},
		{"empty supervisor", func(o *options) { o.SupervisorSocket = "" }},
		{"zero period", func(o *options) { o.Interval = 0 }},
		{"busy spin", func(o *options) { o.Interval = time.Nanosecond }},
		{"slow recovery", func(o *options) { o.Interval = 2 * time.Second }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := base
			tc.change(&candidate)
			if err := candidate.validate(); err == nil {
				t.Fatal("untrusted watchdog startup scope accepted")
			}
		})
	}
}

func TestWatchdogCLIRefusesUnprovisionedTrustedRootService(t *testing.T) {
	cfg := validOptions(t)
	if err := run(context.Background(), cfg); err == nil {
		t.Fatal("watchdog cannot start without a verified root-owned supervisor")
	}
	if _, err := os.Stat(cfg.JournalPath); !os.IsNotExist(err) {
		t.Fatalf("untrusted supervisor startup must not create or mutate journal, err=%v", err)
	}
}
