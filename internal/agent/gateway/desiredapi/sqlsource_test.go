package desiredapi

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
)

const sourceTestNode = "62c478bb-47c3-4dc6-a363-a2fbde813810"
const sourceTestEpoch = "ea2429da-7540-4e40-ae70-38fd3f19794b"

func TestSQLSourceNilAndMalformedIdentityFailClosed(t *testing.T) {
	if _, err := NewSQLSource(nil); err == nil {
		t.Fatal("nil database was accepted")
	}
	var nilSource *SQLSource
	if _, err := nilSource.Latest(context.Background(), sourceTestNode); err == nil {
		t.Fatal("nil source allowed")
	}
	db := sql.OpenDB(&fakeConnector{reply: &fakeQueryReply{epoch: sourceTestEpoch, seq: 2, member: 3, body: []byte(`{"ok":true}`)}})
	defer db.Close()
	src, err := NewSQLSource(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", "BOGUS", "'; DROP TABLE agent_desired_heads; --", strings.ToUpper(sourceTestNode)} {
		if _, err := src.Latest(context.Background(), invalid); err == nil {
			t.Fatalf("accepted invalid node %q", invalid)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := src.Latest(ctx, sourceTestNode); !errors.Is(err, context.Canceled) {
		t.Fatalf("missing cancellation: %v", err)
	}
}

func TestSQLSourceReadsOnlyNodeScopedViewAndRejectsBadSnapshots(t *testing.T) {
	rep := &fakeQueryReply{epoch: sourceTestEpoch, seq: 2, member: 3, body: []byte(`{"ok":true}`)}
	db := sql.OpenDB(&fakeConnector{reply: rep})
	defer db.Close()
	src, err := NewSQLSource(db)
	if err != nil {
		t.Fatal(err)
	}
	got, err := src.Latest(context.Background(), sourceTestNode)
	if err != nil || got.Epoch != sourceTestEpoch || got.StructuralSequence != 2 || got.MembershipSequence != 3 || string(got.Envelope) != `{"ok":true}` {
		t.Fatalf("bad snapshot %+v, %v", got, err)
	}
	if rep.lastArg != sourceTestNode || !strings.Contains(rep.lastSQL, "agent_desired_current") || !strings.Contains(rep.lastSQL, "node_id=$1") {
		t.Fatalf("unexpected SQL boundary: %q arg=%q", rep.lastSQL, rep.lastArg)
	}
	got.Envelope[0] = 0
	if string(rep.body) != `{"ok":true}` {
		t.Fatal("returned buffer aliases database driver data")
	}
	for _, tc := range []struct {
		label  string
		epoch  string
		seq    int64
		member int64
		body   []byte
	}{
		{"missing epoch", "", 2, 3, []byte(`{}`)},
		{"negative seq", sourceTestEpoch, -1, 3, []byte(`{}`)},
		{"zero seq", sourceTestEpoch, 0, 3, []byte(`{}`)},
		{"negative membership", sourceTestEpoch, 2, -1, []byte(`{}`)},
		{"empty envelope", sourceTestEpoch, 2, 3, nil},
		{"oversized envelope", sourceTestEpoch, 2, 3, make([]byte, 1<<20+1)},
	} {
		rep.epoch, rep.seq, rep.member, rep.body = tc.epoch, tc.seq, tc.member, tc.body
		if _, err := src.Latest(context.Background(), sourceTestNode); err == nil {
			t.Errorf("%s admitted", tc.label)
		}
	}
	rep.noRows = true
	if _, err := src.Latest(context.Background(), sourceTestNode); !errors.Is(err, ErrSnapshotUnavailable) {
		t.Fatalf("no row not denied: %v", err)
	}
}

type fakeQueryReply struct {
	epoch            string
	seq, member      int64
	body             []byte
	lastArg, lastSQL string
	noRows           bool
}
type fakeConnector struct{ reply *fakeQueryReply }

func (f *fakeConnector) Connect(context.Context) (driver.Conn, error) {
	return &fakeConn{r: f.reply}, nil
}
func (f *fakeConnector) Driver() driver.Driver { return &fakeDriver{r: f.reply} }

type fakeDriver struct{ r *fakeQueryReply }

func (f *fakeDriver) Open(string) (driver.Conn, error) { return &fakeConn{r: f.r}, nil }

type fakeConn struct{ r *fakeQueryReply }

func (f *fakeConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not implemented") }
func (f *fakeConn) Close() error                        { return nil }
func (f *fakeConn) Begin() (driver.Tx, error)           { return nil, errors.New("not implemented") }
func (f *fakeConn) QueryContext(_ context.Context, sql string, args []driver.NamedValue) (driver.Rows, error) {
	f.r.lastSQL = sql
	if len(args) != 1 {
		return nil, errors.New("invalid bindings")
	}
	f.r.lastArg, _ = args[0].Value.(string)
	if f.r.noRows {
		return &fakeRows{data: nil}, nil
	}
	return &fakeRows{data: []driver.Value{f.r.epoch, f.r.seq, f.r.member, f.r.body}}, nil
}

type fakeRows struct {
	data []driver.Value
	done bool
}

func (r *fakeRows) Columns() []string {
	return []string{"control_plane_epoch", "structural_sequence", "membership_sequence", "envelope"}
}
func (r *fakeRows) Close() error { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.done || r.data == nil {
		return io.EOF
	}
	copy(dest, r.data)
	r.done = true
	return nil
}
