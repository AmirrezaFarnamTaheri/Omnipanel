package adminruntime

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
)

type aclConnector struct {
	rights map[string]bool
	fail   error
	sql    string
}

func (c *aclConnector) Connect(context.Context) (driver.Conn, error) { return &aclConn{c}, nil }
func (c *aclConnector) Driver() driver.Driver                        { return &aclDriver{c} }

type aclDriver struct{ c *aclConnector }

func (d *aclDriver) Open(string) (driver.Conn, error) { return &aclConn{d.c}, nil }

type aclConn struct{ c *aclConnector }

func (c *aclConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("no prepare") }
func (c *aclConn) Close() error                        { return nil }
func (c *aclConn) Begin() (driver.Tx, error)           { return nil, errors.New("no transactions") }
func (c *aclConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	c.c.sql = q
	if c.c.fail != nil {
		return nil, c.c.fail
	}
	return &aclRows{keys: aclExpectedKeys(c.c.rights), rights: c.c.rights}, nil
}

type aclRows struct {
	keys   []string
	pos    int
	rights map[string]bool
}

func (r *aclRows) Columns() []string { return []string{"check", "granted"} }
func (r *aclRows) Close() error      { return nil }
func (r *aclRows) Next(out []driver.Value) error {
	if r.pos == len(r.keys) {
		return io.EOF
	}
	k := r.keys[r.pos]
	r.pos++
	out[0] = k
	out[1] = r.rights[k]
	return nil
}
func aclExpectedKeys(m map[string]bool) []string {
	a := make([]string, 0, len(m))
	for k := range m {
		a = append(a, k)
	}
	return a
}

func newACLDB(t *testing.T, role string, mutate func(map[string]bool)) (*sql.DB, *aclConnector) {
	t.Helper()
	rights := map[string]bool{}
	for k, v := range requiredACL(role) {
		rights[k] = v
	}
	if mutate != nil {
		mutate(rights)
	}
	c := &aclConnector{rights: rights}
	db := sql.OpenDB(c)
	return db, c
}
func TestACLRejectsOverprivilegedAndIncompleteRoles(t *testing.T) {
	for _, role := range []string{"session", "propose", "review"} {
		t.Run(role+"/clean", func(t *testing.T) {
			db, c := newACLDB(t, role, nil)
			defer db.Close()
			if err := VerifyPostgresACL(context.Background(), db, role); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(c.sql, "pg_catalog.has_column_privilege") || !strings.Contains(c.sql, "pg_catalog.has_schema_privilege") {
				t.Fatal("ACL query omitted catalog checks")
			}
		})
		for _, tc := range []struct {
			name, key string
			value     bool
		}{
			{"secret-read", "admin_password_select", true},
			{"TOTP-update", "admin_totp_update", true},
			{"public-schema-ddl", "public_schema_create", true},
			{"table-ownership", "owns_managed_table", true},
			{"unexpected-approval-delete", "approvals_delete", true},
			{"search-path-drift", "search_path_exact", false},
			{"missing-session-visibility", "session_lookup_select", false},
		} {
			t.Run(role+"/"+tc.name, func(t *testing.T) {
				db, _ := newACLDB(t, role, func(m map[string]bool) { m[tc.key] = tc.value })
				defer db.Close()
				if err := VerifyPostgresACL(context.Background(), db, role); err == nil {
					t.Fatalf("unsafe ACL granted for %s", tc.key)
				}
			})
		}
	}
}
func TestACLRoleSpecificWriteSeparation(t *testing.T) {
	for _, tc := range []struct {
		role, key string
		value     bool
	}{
		{"session", "proposals_insert", true},
		{"session", "approvals_insert", true},
		{"propose", "decisions_insert", true},
		{"propose", "proposals_insert", false},
		{"review", "proposals_insert", true},
		{"review", "decisions_insert", false},
	} {
		t.Run(tc.role+"/"+tc.key, func(t *testing.T) {
			db, _ := newACLDB(t, tc.role, func(m map[string]bool) { m[tc.key] = tc.value })
			defer db.Close()
			if err := VerifyPostgresACL(context.Background(), db, tc.role); err == nil {
				t.Fatal("role-specific excess privilege or missing grant admitted")
			}
		})
	}
}
func TestACLRefusesStoreFailuresAndInvalidRoles(t *testing.T) {
	if err := VerifyPostgresACL(context.Background(), nil, "session"); err == nil {
		t.Fatal("nil DB admitted")
	}
	db, c := newACLDB(t, "session", nil)
	defer db.Close()
	if err := VerifyPostgresACL(context.Background(), db, "publisher"); err == nil {
		t.Fatal("unqualified role admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(VerifyPostgresACL(ctx, db, "session"), context.Canceled) {
		t.Fatal("cancelled ACL check admitted")
	}
	c.fail = errors.New("database offline")
	if err := VerifyPostgresACL(context.Background(), db, "session"); err == nil {
		t.Fatal("ACL database failure admitted")
	}
}

func TestSessionACLRequiresSameGlobalRowLockGuard(t *testing.T) {
	if !requiredACL("session")["auth_lock_guard_enabled"] {
		t.Fatal("session role must require the shared protected authentication table trigger, not its absence")
	}
}

func TestACLRequiresProtectedLockColumnGrants(t *testing.T) {
	for _, role := range []string{"propose", "review"} {
		for _, key := range []string{"admin_lock_update", "session_lock_update", "stepup_lock_update"} {
			if !requiredACL(role)[key] {
				t.Fatalf("%s missing essential lock grant %s", role, key)
			}
		}
	}
	if !requiredACL("review")["proposal_lock_update"] || requiredACL("propose")["proposal_lock_update"] || requiredACL("session")["admin_lock_update"] {
		t.Fatal("row-lock UPDATE privileges leaked across roles")
	}
}

func TestACLRequiresCanonicalPurposeIdentity(t *testing.T) {
	for _, role := range []string{"session", "propose", "review"} {
		if !requiredACL(role)["role_purpose_identity"] {
			t.Fatalf("%s did not require its exact authenticated database identity", role)
		}
	}
}

func TestCanonicalRuntimePrincipalPurposeMapping(t *testing.T) {
	for purpose, name := range map[string]string{"session": "omni_desired_session", "propose": "omni_desired_proposer", "review": "omni_desired_reviewer"} {
		if got := ExpectedPrincipal(purpose); got != name {
			t.Fatalf("%s expected database role %q, got %q", purpose, name, got)
		}
	}
	if ExpectedPrincipal("publisher") != "" {
		t.Fatal("unapproved database role was mapped to a privileged principal")
	}
}
