package adminruntime

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ACLCheck is one fixed, read-only catalog predicate. All identifiers and
// SQL expressions are compile-time constants: no request or configuration
// value is interpolated into SQL. The policy deliberately fails closed.
type ACLCheck struct {
	name    string
	sql     string
	session bool
	propose bool
	review  bool
}

// This is a minimum, *not* a full database-security audit. The guarded
// administrator roles additionally need audited role provisioning, a protected
// row-lock UPDATE trigger, table/column GRANT review and real PostgreSQL tests.
var aclChecks = []ACLCheck{
	{"search_path_exact", "pg_catalog.current_setting('search_path') = 'pg_catalog, public'", true, true, true},
	{"public_schema_usage", "pg_catalog.has_schema_privilege(current_user,'public','USAGE')", true, true, true},
	{"public_schema_create", "pg_catalog.has_schema_privilege(current_user,'public','CREATE')", false, false, false},
	{"database_create", "pg_catalog.has_database_privilege(current_user,pg_catalog.current_database(),'CREATE')", false, false, false},
	{"owns_managed_table", `EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) AND c.relkind IN ('r','p','v','m','S','f'))`, false, false, false},

	{"admin_identity_select", "pg_catalog.has_column_privilege(current_user,'public.admins','id','SELECT')", true, true, true},
	{"admin_role_select", "pg_catalog.has_column_privilege(current_user,'public.admins','role','SELECT')", true, true, true},
	{"admin_totp_enabled_select", "pg_catalog.has_column_privilege(current_user,'public.admins','totp_enabled','SELECT')", true, true, true},
	{"session_lookup_select", "pg_catalog.has_column_privilege(current_user,'public.admin_sessions','token_hash','SELECT')", true, true, true},
	{"session_created_select", "pg_catalog.has_column_privilege(current_user,'public.admin_sessions','created_at','SELECT')", true, true, true},
	{"session_last_seen_select", "pg_catalog.has_column_privilege(current_user,'public.admin_sessions','last_seen_at','SELECT')", true, true, true},
	{"session_expiry_select", "pg_catalog.has_column_privilege(current_user,'public.admin_sessions','expires_at','SELECT')", true, true, true},
	{"admin_lock_update", "pg_catalog.has_column_privilege(current_user,'public.admins','id','UPDATE')", false, true, true},
	{"session_lock_update", "pg_catalog.has_column_privilege(current_user,'public.admin_sessions','id','UPDATE')", false, true, true},
	{"stepup_lock_update", "pg_catalog.has_column_privilege(current_user,'public.agent_grant_stepups','session_id','UPDATE')", false, true, true},
	{"proposal_lock_update", "pg_catalog.has_column_privilege(current_user,'public.agent_desired_publish_proposals','proposal_id','UPDATE')", false, false, true},
	{"admin_password_select", "pg_catalog.has_column_privilege(current_user,'public.admins','password_hash','SELECT')", false, false, false},
	{"admin_password_update", "pg_catalog.has_column_privilege(current_user,'public.admins','password_hash','UPDATE')", false, false, false},
	{"admin_totp_select", "pg_catalog.has_column_privilege(current_user,'public.admins','totp_secret_enc','SELECT')", false, false, false},
	{"admin_totp_update", "pg_catalog.has_column_privilege(current_user,'public.admins','totp_secret_enc','UPDATE')", false, false, false},
	{"endpoint_credential_select", "pg_catalog.has_column_privilege(current_user,'public.endpoint_principals','credential_enc','SELECT')", false, false, false},
	{"inbound_secrets_select", "pg_catalog.has_column_privilege(current_user,'public.inbounds','secrets','SELECT')", false, false, false},
	{"settings_value_select", "pg_catalog.has_column_privilege(current_user,'public.settings','value','SELECT')", false, false, false},

	{"proposals_insert", "pg_catalog.has_column_privilege(current_user,'public.agent_desired_publish_proposals','proposal_id','INSERT')", false, true, false},
	{"proposals_envelope_select", "pg_catalog.has_column_privilege(current_user,'public.agent_desired_publish_proposals','envelope','SELECT')", false, false, true},
	{"approvals_insert", "pg_catalog.has_column_privilege(current_user,'public.agent_desired_publish_approvals','approval_id','INSERT')", false, false, true},
	{"decisions_insert", "pg_catalog.has_column_privilege(current_user,'public.agent_desired_publish_decisions','proposal_id','INSERT')", false, false, true},
	{"approvals_update", "pg_catalog.has_column_privilege(current_user,'public.agent_desired_publish_approvals','consumed_at','UPDATE')", false, false, false},
	{"proposals_delete", "pg_catalog.has_table_privilege(current_user,'public.agent_desired_publish_proposals','DELETE')", false, false, false},
	{"approvals_delete", "pg_catalog.has_table_privilege(current_user,'public.agent_desired_publish_approvals','DELETE')", false, false, false},
	{"decisions_delete", "pg_catalog.has_table_privilege(current_user,'public.agent_desired_publish_decisions','DELETE')", false, false, false},
	{"sessions_delete", "pg_catalog.has_table_privilege(current_user,'public.admin_sessions','DELETE')", false, false, false},
	{"admins_delete", "pg_catalog.has_table_privilege(current_user,'public.admins','DELETE')", false, false, false},
	{"auth_lock_guard_enabled", `NOT EXISTS (SELECT 1 FROM (VALUES ('admins'),('admin_sessions'),('agent_desired_publish_permissions'),('agent_grant_stepups'),('agent_grant_node_bindings'),('agent_grant_organizations'),('nodes')) AS protected_table(name) WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_proc f ON f.oid=t.tgfoid WHERE n.nspname='public' AND c.relname=protected_table.name AND t.tgname='omni_runtime_lockonly_update_deny' AND t.tgenabled IN ('O','A') AND f.proname='omni_deny_runtime_lockonly_updates'))`, true, true, true},
}

// ExpectedPrincipal is the only accepted login identity for each runtime pool.
// The DBA grants and immutable row-lock triggers bind to these exact names.
func ExpectedPrincipal(purpose string) string {
	switch purpose {
	case "session":
		return "omni_desired_session"
	case "propose":
		return "omni_desired_proposer"
	case "review":
		return "omni_desired_reviewer"
	default:
		return ""
	}
}

func requiredACL(role string) map[string]bool {
	expected := make(map[string]bool, len(aclChecks))
	for _, check := range aclChecks {
		switch role {
		case "session":
			expected[check.name] = check.session
		case "propose":
			expected[check.name] = check.propose
		case "review":
			expected[check.name] = check.review
		}
	}
	if ExpectedPrincipal(role) != "" {
		expected["role_purpose_identity"] = true
	}
	return expected
}

// VerifyPostgresACL rejects obvious extra privileges and missing grants for
// the exact runtime function. It must be called on each authenticated pool
// after role verification and before exposing the listener. A successful
// check does NOT prove every table/sequence/function ACL is least privileged.
func VerifyPostgresACL(ctx context.Context, db *sql.DB, role string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if db == nil || ExpectedPrincipal(role) == "" {
		return errors.New("invalid runtime ACL preflight configuration")
	}
	expected := requiredACL(role)
	entries := make([]string, 0, len(aclChecks))
	for _, check := range aclChecks {
		entries = append(entries, fmt.Sprintf("('%s', %s)", check.name, check.sql))
	}
	// The value below is chosen from fixed constants, never user input.
	entries = append(entries, fmt.Sprintf("('role_purpose_identity', session_user = '%s')", ExpectedPrincipal(role)))
	query := "SELECT check_name, granted FROM (VALUES " + strings.Join(entries, ",") + ") AS acl_checks(check_name, granted)"
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return errors.New("cannot inspect administrator database permissions")
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var name string
		var granted bool
		if err := rows.Scan(&name, &granted); err != nil {
			return errors.New("invalid database permission result")
		}
		want, ok := expected[name]
		if !ok || seen[name] || want != granted {
			return errors.New("database role lacks required separation or has excess permissions")
		}
		seen[name] = true
	}
	if rows.Err() != nil || len(seen) != len(expected) {
		return errors.New("incomplete administrator database permission inspection")
	}
	return nil
}
