package adminruntime

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
)

var pgRolePattern = regexp.MustCompile(`^[a-z_][a-z0-9_]{2,62}$`)

// VerifyPostgresRole proves the connection is using its independently named,
// nonprivileged database principal. It is a startup floor, not a substitute
// for migration-managed table/column privileges or external ACL review.
func VerifyPostgresRole(ctx context.Context, db *sql.DB, expectedUser string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if db == nil || !pgRolePattern.MatchString(expectedUser) {
		return errors.New("database role verification configuration missing")
	}
	var actual, authenticated string
	var canLogin, superuser, createdb, createrole, replication, bypassrls, hasMembership bool
	// Deny role membership, including NOINHERIT or SET ROLE, in addition
	// to direct privileges. Prove session_user equals the expected principal.
	const stmt = `SELECT current_user, session_user, r.rolcanlogin, r.rolsuper, r.rolcreatedb, r.rolcreaterole, r.rolreplication, r.rolbypassrls,
 EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=r.oid)
 FROM pg_catalog.pg_roles r WHERE r.rolname=current_user`
	if err := db.QueryRowContext(ctx, stmt).Scan(&actual, &authenticated, &canLogin, &superuser, &createdb, &createrole, &replication, &bypassrls, &hasMembership); err != nil {
		return errors.New("cannot verify live database role")
	}
	if actual != expectedUser || authenticated != expectedUser || !canLogin || superuser || createdb || createrole || replication || bypassrls || hasMembership {
		return errors.New("database principal is incorrect or overprivileged")
	}
	return nil
}
