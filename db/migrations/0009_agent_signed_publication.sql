-- OmniPanel v2: bounded, independently preapproved signed-state publication.
-- Requires migrations 0001-0008; this does NOT expose an approval writer,
-- signing service, recovery API, deployed publisher or elevated gateway role.
BEGIN;

-- Signed-state publisher permissions are deliberately separate from node
-- ENROLLMENT-grant scopes. Grant issuance must never imply permission to
-- publish executable node configuration.
CREATE TABLE agent_desired_publish_permissions (
    admin_id integer NOT NULL REFERENCES admins(id) ON DELETE RESTRICT,
    organization_id uuid NOT NULL REFERENCES agent_grant_organizations(organization_id) ON DELETE RESTRICT,
    can_propose boolean NOT NULL DEFAULT false,
    can_approve boolean NOT NULL DEFAULT false,
    PRIMARY KEY (admin_id, organization_id)
);

-- Approval rows must originate from a separately protected administrator
-- approval workflow. The publisher can consume a matching, unexpired approval
-- but may not create or change its identity, digest or scope.
CREATE TABLE agent_desired_publish_approvals (
    approval_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES agent_grant_organizations(organization_id),
    node_id uuid NOT NULL,
    control_plane_epoch uuid NOT NULL,
    structural_sequence bigint NOT NULL CHECK (structural_sequence BETWEEN 1 AND 9007199254740991),
    membership_sequence bigint NOT NULL CHECK (membership_sequence BETWEEN 0 AND 9007199254740991),
    envelope_sha256 bytea NOT NULL CHECK (octet_length(envelope_sha256) = 32),
    issuer_admin_id integer NOT NULL REFERENCES admins(id),
    approver_admin_id integer NOT NULL REFERENCES admins(id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    FOREIGN KEY (node_id, organization_id)
        REFERENCES agent_grant_node_bindings(node_id, organization_id),
    CHECK (issuer_admin_id <> approver_admin_id),
    CHECK (expires_at > created_at)
);
CREATE INDEX agent_desired_publish_approvals_node
    ON agent_desired_publish_approvals(node_id, expires_at)
    WHERE consumed_at IS NULL;

CREATE FUNCTION protect_agent_desired_publish_approval() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'publication approvals are durable history';
    END IF;
    IF OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL
       OR (to_jsonb(NEW) - 'consumed_at') IS DISTINCT FROM (to_jsonb(OLD) - 'consumed_at') THEN
        RAISE EXCEPTION 'publication approval scope is immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER agent_desired_publish_approvals_protected
    BEFORE UPDATE OR DELETE ON agent_desired_publish_approvals
    FOR EACH ROW EXECUTE FUNCTION protect_agent_desired_publish_approval();

CREATE TABLE agent_desired_publish_audit (
    audit_id bigserial PRIMARY KEY,
    approval_id uuid NOT NULL UNIQUE REFERENCES agent_desired_publish_approvals(approval_id),
    node_id uuid NOT NULL,
    control_plane_epoch uuid NOT NULL,
    structural_sequence bigint NOT NULL,
    membership_sequence bigint NOT NULL,
    envelope_sha256 bytea NOT NULL CHECK (octet_length(envelope_sha256) = 32),
    issuer_admin_id integer NOT NULL REFERENCES admins(id),
    approver_admin_id integer NOT NULL REFERENCES admins(id),
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (node_id, control_plane_epoch, structural_sequence)
        REFERENCES agent_desired_revisions(node_id, control_plane_epoch, structural_sequence)
        ON DELETE RESTRICT,
    CHECK (issuer_admin_id <> approver_admin_id)
);
CREATE TABLE agent_desired_publish_outbox (
    audit_id bigint PRIMARY KEY REFERENCES agent_desired_publish_audit(audit_id) ON DELETE RESTRICT,
    node_id uuid NOT NULL,
    structural_sequence bigint NOT NULL CHECK (structural_sequence > 0),
    enqueued_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION prevent_agent_desired_publication_history_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'signed publication audit/outbox records are append only';
END;
$$;
CREATE TRIGGER agent_desired_publish_audit_immutable
    BEFORE UPDATE OR DELETE ON agent_desired_publish_audit
    FOR EACH ROW EXECUTE FUNCTION prevent_agent_desired_publication_history_mutation();
CREATE TRIGGER agent_desired_publish_outbox_immutable
    BEFORE UPDATE OR DELETE ON agent_desired_publish_outbox
    FOR EACH ROW EXECUTE FUNCTION prevent_agent_desired_publication_history_mutation();

-- No credentials are provisioned by a migration. A future separate publish
-- role must receive only SELECT + consumed_at UPDATE on approvals, minimal
-- INSERT/UPDATE for revisions/heads, INSERT for audit/outbox, and SELECT on
-- the live authorization tables. A read-only gateway must have NONE of these.
REVOKE ALL ON TABLE agent_desired_publish_permissions,
    agent_desired_publish_approvals, agent_desired_publish_audit,
    agent_desired_publish_outbox FROM PUBLIC;
REVOKE ALL ON SEQUENCE agent_desired_publish_audit_audit_id_seq FROM PUBLIC;

COMMIT;
