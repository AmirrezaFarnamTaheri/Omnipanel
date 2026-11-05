package httpapi

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

type localSessionConnector struct {
	arg        string
	sql        string
	valid      bool
	queryCalls int
	fail       error
}

func (f *localSessionConnector) Connect(context.Context) (driver.Conn, error) {
	return &localSessionConn{f}, nil
}
func (f *localSessionConnector) Driver() driver.Driver { return &localSessionDriver{f} }

type localSessionDriver struct{ r *localSessionConnector }

func (d *localSessionDriver) Open(string) (driver.Conn, error) { return &localSessionConn{d.r}, nil }

type localSessionConn struct{ r *localSessionConnector }

func (d *localSessionConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements disallowed")
}
func (d *localSessionConn) Close() error { return nil }
func (d *localSessionConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions disallowed")
}
func (d *localSessionConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	d.r.queryCalls++
	d.r.sql = q
	if len(args) != 1 {
		return nil, errors.New("expected parameterized hash only")
	}
	d.r.arg, _ = args[0].Value.(string)
	if d.r.fail != nil {
		return nil, d.r.fail
	}
	return &localSessionRows{d.r.valid, false}, nil
}

type localSessionRows struct {
	answer bool
	done   bool
}

func (*localSessionRows) Columns() []string { return []string{"exists"} }
func (*localSessionRows) Close() error      { return nil }
func (r *localSessionRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.answer
	return nil
}

func TestLiveSQLSessionCheckerUsesHashedBearerAndOwnerState(t *testing.T) {
	if _, err := NewSQLSessionChecker(nil); err == nil {
		t.Fatal("nil database admitted")
	}
	fake := &localSessionConnector{valid: true}
	db := sql.OpenDB(fake)
	defer db.Close()
	checker, err := NewSQLSessionChecker(db)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := checker.Active(context.Background(), sessionToken)
	if err != nil || !ok {
		t.Fatalf("live session denied: %v", err)
	}
	hash := sha256.Sum256([]byte(sessionToken))
	if fake.arg != hex.EncodeToString(hash[:]) || !strings.Contains(fake.sql, "admin_sessions") || !strings.Contains(fake.sql, "a.role='owner'") {
		t.Fatal("session check failed to bind hashed live owner credential")
	}
	if fake.arg == sessionToken {
		t.Fatal("plaintext session exposed to SQL query")
	}
	fake.valid = false
	ok, err = checker.Active(context.Background(), sessionToken)
	if err != nil || ok {
		t.Fatalf("revoked owner still admitted: %v", err)
	}
	before := fake.queryCalls
	ok, err = checker.Active(context.Background(), "bad")
	if err != nil || ok || fake.queryCalls != before {
		t.Fatalf("invalid token entered database: %v", err)
	}
	fake.fail = errors.New("database down")
	if ok, err = checker.Active(context.Background(), sessionToken); err == nil || ok {
		t.Fatal("database outage failed open")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ok, err = checker.Active(ctx, sessionToken); !errors.Is(err, context.Canceled) || ok {
		t.Fatalf("cancelled request entered database: %v", err)
	}
	var nilChecker *SQLSessionChecker
	if ok, err = nilChecker.Active(context.Background(), sessionToken); err == nil || ok {
		t.Fatal("nil checker admitted session")
	}
}
