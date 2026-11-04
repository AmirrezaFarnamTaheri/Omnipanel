package observability

import (
	"errors"
	"math"
	"testing"
	"time"
)

func validSnapshot(now time.Time) Snapshot {
	return Snapshot{NodeID: "node-a", Generation: 1, SampledAt: now, CPUPercent: 42.5, MemoryTotalBytes: 100, MemoryUsedBytes: 60,
		Filesystems: []Filesystem{{ID: "/", TotalBytes: 1000, UsedBytes: 700}}, Network: []NetworkCounters{{Interface: "eth0", ReceivedBytes: 10, SentBytes: 20}}}
}

func TestResourceSnapshotValidationAndFreshness(t *testing.T) {
	now := time.Now().UTC()
	s := validSnapshot(now.Add(-time.Minute))
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := s.Classify(now, 2*time.Minute); got != Fresh {
		t.Fatalf("fresh sample classified %q", got)
	}
	if got := s.Classify(now, 30*time.Second); got != Stale {
		t.Fatalf("old sample classified %q", got)
	}
	if got := validSnapshot(now.Add(time.Second)).Classify(now, time.Minute); got != Unknown {
		t.Fatalf("future sample classified %q", got)
	}
	if got := s.Classify(now, 0); got != Unknown {
		t.Fatalf("invalid freshness window classified %q", got)
	}
}

func TestResourceSnapshotRejectsInvalidMeasurements(t *testing.T) {
	now := time.Now().UTC()
	cases := map[string]func(*Snapshot){
		"missing generation":   func(s *Snapshot) { s.Generation = 0 },
		"cpu nan":              func(s *Snapshot) { s.CPUPercent = math.NaN() },
		"cpu infinity":         func(s *Snapshot) { s.CPUPercent = math.Inf(1) },
		"cpu range":            func(s *Snapshot) { s.CPUPercent = 100.1 },
		"memory overflow":      func(s *Snapshot) { s.MemoryUsedBytes = s.MemoryTotalBytes + 1 },
		"filesystem overflow":  func(s *Snapshot) { s.Filesystems[0].UsedBytes = s.Filesystems[0].TotalBytes + 1 },
		"duplicate filesystem": func(s *Snapshot) { s.Filesystems = append(s.Filesystems, s.Filesystems[0]) },
		"duplicate interface":  func(s *Snapshot) { s.Network = append(s.Network, s.Network[0]) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := validSnapshot(now)
			mutate(&s)
			if err := s.Validate(); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("expected invalid snapshot, got %v", err)
			}
			if s.Classify(now, time.Minute) != Unknown {
				t.Fatal("invalid snapshot received a health classification")
			}
		})
	}
}

func TestResourceSnapshotsAreNotProxyHealth(t *testing.T) {
	s := validSnapshot(time.Now())
	// A valid host sample only establishes resource-data validity/freshness.
	// It contains no listener, traffic, endpoint, or client-connectivity claim.
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
}
