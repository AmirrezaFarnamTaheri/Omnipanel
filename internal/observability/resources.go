// Package observability defines validated, read-only node resource snapshots.
// These host metrics are not proxy health, traffic accounting, or enforcement.
package observability

import (
	"errors"
	"math"
	"strings"
	"time"
)

var ErrInvalidSnapshot = errors.New("invalid resource snapshot")

type Filesystem struct {
	ID         string
	TotalBytes uint64
	UsedBytes  uint64
}

type NetworkCounters struct {
	Interface     string
	ReceivedBytes uint64
	SentBytes     uint64
}

type Snapshot struct {
	NodeID           string
	Generation       uint64
	SampledAt        time.Time
	CPUPercent       float64
	MemoryTotalBytes uint64
	MemoryUsedBytes  uint64
	Filesystems      []Filesystem
	Network          []NetworkCounters
}

type Freshness string

const (
	Fresh   Freshness = "fresh"
	Stale   Freshness = "stale"
	Unknown Freshness = "unknown"
)

func (s Snapshot) Validate() error {
	if strings.TrimSpace(s.NodeID) == "" || len(s.NodeID) > 128 || s.Generation == 0 || s.SampledAt.IsZero() || math.IsNaN(s.CPUPercent) || math.IsInf(s.CPUPercent, 0) || s.CPUPercent < 0 || s.CPUPercent > 100 || s.MemoryTotalBytes == 0 || s.MemoryUsedBytes > s.MemoryTotalBytes || len(s.Filesystems) > 256 || len(s.Network) > 256 {
		return ErrInvalidSnapshot
	}
	seenFS := make(map[string]struct{}, len(s.Filesystems))
	for _, fs := range s.Filesystems {
		if strings.TrimSpace(fs.ID) == "" || len(fs.ID) > 256 || fs.TotalBytes == 0 || fs.UsedBytes > fs.TotalBytes {
			return ErrInvalidSnapshot
		}
		if _, exists := seenFS[fs.ID]; exists {
			return ErrInvalidSnapshot
		}
		seenFS[fs.ID] = struct{}{}
	}
	seenNet := make(map[string]struct{}, len(s.Network))
	for _, n := range s.Network {
		if strings.TrimSpace(n.Interface) == "" || len(n.Interface) > 128 {
			return ErrInvalidSnapshot
		}
		if _, exists := seenNet[n.Interface]; exists {
			return ErrInvalidSnapshot
		}
		seenNet[n.Interface] = struct{}{}
	}
	return nil
}

// Classify returns unknown for invalid inputs or a future-dated sample. Resource
// freshness is independent of inbound reachability and runtime health.
func (s Snapshot) Classify(now time.Time, maxAge time.Duration) Freshness {
	if s.Validate() != nil || now.IsZero() || maxAge <= 0 || s.SampledAt.After(now) {
		return Unknown
	}
	if now.Sub(s.SampledAt) > maxAge {
		return Stale
	}
	return Fresh
}
