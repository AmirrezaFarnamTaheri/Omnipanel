// Package syncfeed defines bounded cursor/tombstone page validation for node
// inventory synchronization. It validates feed structure only; it does not
// authenticate, sign, persist, apply, or authorize any record.
package syncfeed

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	MaxPageRecords        = 512
	MaxRecordIDBytes      = 256
	MaxRecordPayloadBytes = 1 << 20
	MaxPagePayloadBytes   = 8 << 20
)

var (
	ErrInvalidPage    = errors.New("invalid sync feed page")
	ErrCursorMismatch = errors.New("sync feed cursor mismatch")
	ErrResyncRequired = errors.New("sync feed gap requires full resynchronization")
)

type Record struct {
	Sequence  uint64
	ID        string
	Tombstone bool
	Payload   []byte
}

type Page struct {
	BaseCursor uint64
	NextCursor uint64
	Records    []Record
	Digest     string
}

// ValidatePage requires contiguous, bounded entries and a canonical digest.
// A structurally sound page advances exactly through its last sequence.
func ValidatePage(current uint64, page Page) (uint64, error) {
	if current != page.BaseCursor {
		return current, ErrCursorMismatch
	}
	if len(page.Records) > MaxPageRecords || page.NextCursor < page.BaseCursor {
		return current, ErrInvalidPage
	}
	if uint64(len(page.Records)) > ^uint64(0)-page.BaseCursor {
		return current, ErrInvalidPage
	}
	expectedNext := page.BaseCursor + uint64(len(page.Records))
	if page.NextCursor != expectedNext {
		return current, ErrInvalidPage
	}
	ids := make(map[string]struct{}, len(page.Records))
	var size int
	for i, record := range page.Records {
		if record.Sequence != page.BaseCursor+uint64(i)+1 {
			return current, ErrResyncRequired
		}
		if strings.TrimSpace(record.ID) == "" || len(record.ID) > MaxRecordIDBytes {
			return current, ErrInvalidPage
		}
		if _, ok := ids[record.ID]; ok {
			return current, ErrInvalidPage
		}
		ids[record.ID] = struct{}{}
		if record.Tombstone && len(record.Payload) != 0 {
			return current, ErrInvalidPage
		}
		if len(record.Payload) > MaxRecordPayloadBytes {
			return current, ErrInvalidPage
		}
		size += len(record.Payload)
		if size > MaxPagePayloadBytes {
			return current, ErrInvalidPage
		}
	}
	if page.Digest != Digest(page.Records) {
		return current, fmt.Errorf("%w: digest mismatch", ErrInvalidPage)
	}
	return page.NextCursor, nil
}

// Digest hashes each ordered record using unambiguous length-prefixed fields.
// It is an integrity checksum only; callers must authenticate/sign the page.
func Digest(records []Record) string {
	h := sha256.New()
	var size [8]byte
	for _, record := range records {
		binary.BigEndian.PutUint64(size[:], record.Sequence)
		_, _ = h.Write(size[:])
		binary.BigEndian.PutUint64(size[:], uint64(len(record.ID)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(record.ID))
		if record.Tombstone {
			_, _ = h.Write([]byte{1})
		} else {
			_, _ = h.Write([]byte{0})
		}
		binary.BigEndian.PutUint64(size[:], uint64(len(record.Payload)))
		_, _ = h.Write(size[:])
		_, _ = h.Write(record.Payload)
	}
	return hex.EncodeToString(h.Sum(nil))
}
