package syncfeed

import (
	"errors"
	"testing"
)

func makePage(base uint64, records []Record) Page {
	p := Page{BaseCursor: base, NextCursor: base + uint64(len(records)), Records: records}
	p.Digest = Digest(records)
	return p
}

func TestValidateContiguousCursorPageAndTombstone(t *testing.T) {
	records := []Record{
		{Sequence: 11, ID: "node/a", Payload: []byte(`{"status":"active"}`)},
		{Sequence: 12, ID: "node/b", Tombstone: true},
	}
	got, err := ValidatePage(10, makePage(10, records))
	if err != nil || got != 12 {
		t.Fatalf("cursor=%d err=%v", got, err)
	}
	if _, err := ValidatePage(10, makePage(10, nil)); err != nil {
		t.Fatalf("empty poll page: %v", err)
	}
	if _, err := ValidatePage(12, makePage(10, records)); !errors.Is(err, ErrCursorMismatch) {
		t.Fatalf("stale page error=%v", err)
	}
}

func TestValidateRejectsGapsDigestAndMalformedTombstones(t *testing.T) {
	cases := map[string]Page{
		"sequence gap":        makePage(4, []Record{{Sequence: 6, ID: "x"}}),
		"bad digest":          {BaseCursor: 0, NextCursor: 1, Records: []Record{{Sequence: 1, ID: "x"}}, Digest: "bad"},
		"payload tombstone":   makePage(0, []Record{{Sequence: 1, ID: "x", Tombstone: true, Payload: []byte("still here")}}),
		"duplicate id":        makePage(0, []Record{{Sequence: 1, ID: "x"}, {Sequence: 2, ID: "x"}}),
		"cursor inconsistent": {BaseCursor: 0, NextCursor: 2, Digest: Digest(nil)},
	}
	for name, page := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ValidatePage(page.BaseCursor, page)
			if err == nil {
				t.Fatal("malformed page accepted")
			}
			if name == "sequence gap" && !errors.Is(err, ErrResyncRequired) {
				t.Fatalf("gap error=%v", err)
			}
		})
	}
}

func TestValidateBoundsPagePayloadAndIdentity(t *testing.T) {
	tooLarge := make([]byte, MaxRecordPayloadBytes+1)
	if _, err := ValidatePage(0, makePage(0, []Record{{Sequence: 1, ID: "x", Payload: tooLarge}})); !errors.Is(err, ErrInvalidPage) {
		t.Fatalf("oversized payload error=%v", err)
	}
	if _, err := ValidatePage(0, makePage(0, []Record{{Sequence: 1, ID: " "}})); !errors.Is(err, ErrInvalidPage) {
		t.Fatalf("blank identity error=%v", err)
	}
	many := make([]Record, MaxPageRecords+1)
	for i := range many {
		many[i] = Record{Sequence: uint64(i + 1), ID: string(rune(i + 1))}
	}
	if _, err := ValidatePage(0, makePage(0, many)); !errors.Is(err, ErrInvalidPage) {
		t.Fatalf("oversized page error=%v", err)
	}
}

func TestDigestIsOrderedAndUnambiguous(t *testing.T) {
	a := []Record{{Sequence: 1, ID: "a", Payload: []byte("bc")}}
	b := []Record{{Sequence: 1, ID: "ab", Payload: []byte("c")}}
	if Digest(a) == Digest(b) {
		t.Fatal("distinct length-prefixed records share digest")
	}
	if Digest(a) == Digest([]Record{{Sequence: 2, ID: "a", Payload: []byte("bc")}}) {
		t.Fatal("sequence not covered by digest")
	}
}
