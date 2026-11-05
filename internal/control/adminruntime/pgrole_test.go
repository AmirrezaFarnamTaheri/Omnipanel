package adminruntime

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"testing"
)

type roleConnector struct {
	values    []driver.Value
	fail      error
	statement string
}

func (c *roleConnector) Connect(context.Context) (driver.Conn, error) { return &roleConn{c}, nil }
func (c *roleConnector) Driver() driver.Driver                        { return &roleDriver{c} }

type roleDriver struct{ c *roleConnector }

func (d *roleDriver) Open(string) (driver.Conn, error) { return &roleConn{d.c}, nil }

type roleConn struct{ c *roleConnector }

func (*roleConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("no prepare") }
func (*roleConn) Close() error                        { return nil }
func (*roleConn) Begin() (driver.Tx, error)           { return nil, errors.New("no transactions") }
func (c *roleConn) QueryContext(_ context.Context, sql string, _ []driver.NamedValue) (driver.Rows, error) {
	c.c.statement = sql
	if c.c.fail != nil {
		return nil, c.c.fail
	}
	return &roleRows{values: c.c.values}, nil
}

type roleRows struct {
	values []driver.Value
	done   bool
}

func (*roleRows) Columns() []string {
	return []string{"current_user", "rolsuper", "rolcreatedb", "rolcreaterole", "rolreplication", "rolbypassrls"}
}
func (*roleRows) Close() error { return nil }
func (r *roleRows) Next(dst []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dst, r.values)
	return nil
}
func TestRoleGuardRequiresActualNonprivilegedSeparateUser(t *testing.T) {
	for _, tc := range []struct {
		name    string
		values  []driver.Value
		fail    error
		wantErr bool
	}{
		{"safe", []driver.Value{"omni_session", false, false, false, false, false}, nil, false},
		{"wrong identity", []driver.Value{"postgres", false, false, false, false, false}, nil, true},
		{"superuser", []driver.Value{"omni_session", true, false, false, false, false}, nil, true},
		{"create database", []driver.Value{"omni_session", false, true, false, false, false}, nil, true},
		{"create roles", []driver.Value{"omni_session", false, false, true, false, false}, nil, true},
		{"replication", []driver.Value{"omni_session", false, false, false, true, false}, nil, true},
		{"bypass row security", []driver.Value{"omni_session", false, false, false, false, true}, nil, true},
		{"database unavailable", nil, errors.New("down"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &roleConnector{values: tc.values, fail: tc.fail}
			db := sql.OpenDB(c)
			defer db.Close()
			err := VerifyPostgresRole(context.Background(), db, "omni_session")
			if (err != nil) != tc.wantErr {
				t.Fatalf("role guard mismatch %v", err)
			}
			if c.statement == "" {
				t.Fatal("no live DB role check")
			}
		})
	}
	if VerifyPostgresRole(context.Background(), nil, "omni_session") == nil {
		t.Fatal("nil db admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	db := sql.OpenDB(&roleConnector{values: []driver.Value{"omni_session", false, false, false, false, false}})
	defer db.Close()
	if !errors.Is(VerifyPostgresRole(ctx, db, "omni_session"), context.Canceled) {
		t.Fatal("cancelled role verification admitted")
	}
}
