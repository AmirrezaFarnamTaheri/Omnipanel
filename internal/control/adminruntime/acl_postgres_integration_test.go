//go:build postgres_integration

package adminruntime

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// This test creates and destroys a wholly disposable database and three
// ephemeral LOGIN roles. Never execute it against a non-test PostgreSQL DSN.
func TestPostgresAdministratorRoleGrants(t *testing.T) {
	source := os.Getenv("OMNIPANEL_TEST_POSTGRES_DSN")
	u, err := url.Parse(source)
	if err != nil || u == nil || u.Scheme != "postgres" || u.Hostname() != "127.0.0.1" ||
		u.Path != "/omnipanel_enrollment_test" || u.User == nil || u.User.Username() != "omni_test" {
		t.Fatal("administrator ACL integration requires isolated CI PostgreSQL only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := sql.Open("postgres", source)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	var salt [6]byte
	if _, err := rand.Read(salt[:]); err != nil {
		t.Fatal(err)
	}
	name := "omni_acl_" + hex.EncodeToString(salt[:])
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	roles := []string{"omni_desired_session", "omni_desired_proposer", "omni_desired_reviewer"}
	const password = "disposable-local-ci-only"
	defer func() {
		// Close all test database pools before dropping the database.
		if _, err := admin.Exec("DROP DATABASE IF EXISTS " + name + " WITH (FORCE)"); err != nil {
			t.Errorf("cleanup isolated ACL database: %v", err)
		}
		for _, role := range roles {
			if _, err := admin.Exec("DROP ROLE IF EXISTS " + role); err != nil {
				t.Errorf("cleanup isolated role: %v", err)
			}
		}
	}()
	for _, role := range roles {
		if _, err := admin.ExecContext(ctx, "CREATE ROLE "+role+" LOGIN PASSWORD '"+password+"'"); err != nil {
			t.Fatal(err)
		}
	}
	u.Path = "/" + name
	super, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range []string{
		"0001_initial.sql", "0002_m2.sql", "0003_agent_enrollment.sql",
		"0004_agent_enrollment_rate_limits.sql", "0005_agent_admin_grants.sql",
		"0006_agent_grant_logout_revocation.sql", "0007_agent_grant_verified_stepup.sql",
		"0008_agent_signed_desired.sql", "0009_agent_signed_publication.sql",
		"0010_agent_desired_dual_approval.sql",
	} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "db", "migrations", migration))
		if err != nil {
			super.Close()
			t.Fatal(err)
		}
		if _, err := super.ExecContext(ctx, string(raw)); err != nil {
			super.Close()
			t.Fatalf("migration %s: %v", migration, err)
		}
	}
	// Trigger under a separate DBA identity, never in the runtime's role.
	if _, err := super.ExecContext(ctx, "INSERT INTO admins (id,email,password_hash,role,totp_enabled) VALUES (1,'acl@test.invalid','none','owner',true)"); err != nil {
		super.Close()
		t.Fatal(err)
	}
	script, err := os.ReadFile(filepath.Join("..", "..", "..", "db", "security", "desired_approval_roles.sql"))
	if err != nil {
		super.Close()
		t.Fatal(err)
	}
	if _, err := super.ExecContext(ctx, string(script)); err != nil {
		super.Close()
		t.Fatalf("role grant script rejected: %v", err)
	}
	if err := super.Close(); err != nil {
		t.Fatal(err)
	}
	for _, role := range roles {
		t.Run(role, func(t *testing.T) {
			connURL := *u
			connURL.User = url.UserPassword(role, password)
			db, err := sql.Open("postgres", connURL.String())
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if err := db.PingContext(ctx); err != nil {
				t.Fatal(err)
			}
			if err := VerifyPostgresRole(ctx, db, role); err != nil {
				t.Fatalf("live role not isolated: %v", err)
			}
			logical := map[string]string{"omni_desired_session": "session", "omni_desired_proposer": "propose", "omni_desired_reviewer": "review"}[role]
			if err := VerifyPostgresACL(ctx, db, logical); err != nil {
				t.Fatalf("live privilege matrix rejected role: %v", err)
			}
			for _, q := range []string{
				"SELECT password_hash FROM public.admins",
				"SELECT totp_secret_enc FROM public.admins",
				"SELECT credential_enc FROM public.endpoint_principals",
				"CREATE TABLE public.omni_acl_forbidden (id integer)",
				"DELETE FROM public.admin_sessions",
			} {
				if _, err := db.ExecContext(ctx, q); err == nil {
					t.Fatalf("excessive role permission accepted: %s", q)
				}
			}
			if _, err := db.ExecContext(ctx, "SELECT id FROM public.admins"); err != nil {
				t.Fatal(err)
			}
			if logical == "session" {
				if _, err := db.ExecContext(ctx, "SELECT token_hash FROM public.admin_sessions"); err != nil {
					t.Fatal(err)
				}
				if _, err := db.ExecContext(ctx, "SELECT id FROM public.admins FOR SHARE"); err == nil {
					t.Fatal("read-only bearer checker received write-lock privilege")
				}
			} else {
				if _, err := db.ExecContext(ctx, "SELECT id FROM public.admins FOR SHARE"); err != nil {
					t.Fatalf("locked authorization SELECT unexpectedly denied: %v", err)
				}
				if _, err := db.ExecContext(ctx, "UPDATE public.admins SET id=id WHERE id=1"); err == nil {
					t.Fatal("role mutated an authentication row despite lock-only grant")
				}
				if logical == "propose" {
					if _, err := db.ExecContext(ctx, "SELECT envelope FROM public.agent_desired_publish_proposals"); err == nil {
						t.Fatal("proposer read other operators' signed proposals")
					}
				} else {
					if _, err := db.ExecContext(ctx, "SELECT proposal_id FROM public.agent_desired_publish_proposals FOR UPDATE"); err != nil {
						t.Fatalf("immutable reviewer lock unavailable: %v", err)
					}
					if _, err := db.ExecContext(ctx, "UPDATE public.agent_desired_publish_proposals SET proposal_id=proposal_id"); err == nil {
						t.Fatal("reviewer updated immutable proposals")
					}
				}
			}
			var effective, authenticated string
			if err := db.QueryRowContext(ctx, "SELECT current_user,session_user").Scan(&effective, &authenticated); err != nil {
				t.Fatal(err)
			}
			if effective != role || authenticated != role {
				t.Fatal(fmt.Sprintf("role impersonated: %q/%q", effective, authenticated))
			}
		})
	}
}
