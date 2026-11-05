-- OmniPanel v2: independently approved UUID-to-legacy-node enrollment grants.
-- Requires legacy admins/admin_sessions/nodes and agent grant migration 0003.
-- Does not deploy a public admin API, certificate issuer or approval writer.
BEGIN;

CREATE TABLE agent_grant_organizations (
    organization_id uuid PRIMARY KEY,
    state text NOT NULL CHECK (state IN ('active', 'suspended'))
);

CREATE TABLE agent_grant_admin_scopes (
    admin_id integer NOT NULL REFERENCES admins(id) ON DELETE RESTRICT,
    organization_id uuid NOT NULL REFERENCES agent_grant_organizations(organization_id) ON DELETE RESTRICT,
    can_issue boolean NOT NULL DEFAULT false,
    can_approve boolean NOT NULL DEFAULT false,
    PRIMARY KEY (admin_id, organization_id)
);

CREATE TABLE agent_grant_stepups (
    session_id integer PRIMARY KEY REFERENCES admin_sessions(id) ON DELETE CASCADE,
    method text NOT NULL CHECK (method = 'totp'),
    verified_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > verified_at)
);

CREATE TABLE agent_grant_node_bindings (
    node_id uuid PRIMARY KEY,
    legacy_node_id integer NOT NULL UNIQUE REFERENCES nodes(id) ON DELETE RESTRICT,
    organization_id uuid NOT NULL REFERENCES agent_grant_organizations(organization_id) ON DELETE RESTRICT,
    state text NOT NULL CHECK (state IN ('pending', 'approved', 'revoked')),
    approved_by integer NOT NULL REFERENCES admins(id) ON DELETE RESTRICT,
    approved_at timestamptz NOT NULL,
    UNIQUE (node_id, organization_id)
);

CREATE TABLE agent_grant_issues (
    issue_id bigserial PRIMARY KEY,
    token_digest bytea NOT NULL UNIQUE REFERENCES agent_enrollment_grants(token_digest) ON DELETE RESTRICT,
    actor_admin_id integer NOT NULL REFERENCES admins(id) ON DELETE RESTRICT,
    session_id integer NOT NULL REFERENCES admin_sessions(id) ON DELETE RESTRICT,
    organization_id uuid NOT NULL,
    node_id uuid NOT NULL,
    correlation_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
    UNIQUE (actor_admin_id, correlation_id),
    FOREIGN KEY (node_id, organization_id)
        REFERENCES agent_grant_node_bindings(node_id, organization_id) ON DELETE RESTRICT
);

CREATE TABLE agent_grant_audit (
    audit_id bigserial PRIMARY KEY,
    issue_id bigint NOT NULL UNIQUE REFERENCES agent_grant_issues(issue_id) ON DELETE RESTRICT,
    actor_admin_id integer NOT NULL REFERENCES admins(id) ON DELETE RESTRICT,
    organization_id uuid NOT NULL,
    node_id uuid NOT NULL,
    token_digest bytea NOT NULL CHECK (octet_length(token_digest) = 32),
    action text NOT NULL CHECK (action = 'grant-issued'),
    correlation_id uuid NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE FUNCTION prevent_agent_grant_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'agent grant audit is append only';
END;
$$;
CREATE TRIGGER agent_grant_audit_no_update_delete
BEFORE UPDATE OR DELETE ON agent_grant_audit
FOR EACH ROW EXECUTE FUNCTION prevent_agent_grant_audit_mutation();

CREATE INDEX agent_grant_issues_node_idx ON agent_grant_issues(node_id, created_at DESC);
CREATE INDEX agent_grant_audit_time_idx ON agent_grant_audit(created_at DESC);

COMMIT;
