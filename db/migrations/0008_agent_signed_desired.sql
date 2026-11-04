-- OmniPanel v2 signed desired-state publication/read boundary (forward-only).
-- Requires 0001-0007, including approved UUID-to-legacy-node bindings.
-- A future privileged publisher must atomically validate/sign/audit changes;
-- this migration supplies immutable revision storage and a scoped read view,
-- NOT an admin publishing service or an epoch-recovery authorization path.
BEGIN;

CREATE TABLE agent_desired_revisions (
    node_id uuid NOT NULL REFERENCES agent_grant_node_bindings(node_id) ON DELETE RESTRICT,
    control_plane_epoch uuid NOT NULL,
    structural_sequence bigint NOT NULL CHECK (structural_sequence BETWEEN 1 AND 9007199254740991),
    membership_sequence bigint NOT NULL CHECK (membership_sequence BETWEEN 0 AND 9007199254740991),
    envelope bytea NOT NULL CHECK (octet_length(envelope) BETWEEN 1 AND 1048576),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (node_id, control_plane_epoch, structural_sequence)
);

-- An independent publisher may advance a head only to an existing immutable
-- node+epoch+sequence revision. Changing epochs requires a separately reviewed
-- recovery operation; it cannot be silently smuggled into an ordinary UPDATE.
CREATE TABLE agent_desired_heads (
    node_id uuid PRIMARY KEY REFERENCES agent_grant_node_bindings(node_id) ON DELETE RESTRICT,
    control_plane_epoch uuid NOT NULL,
    structural_sequence bigint NOT NULL CHECK (structural_sequence BETWEEN 1 AND 9007199254740991),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (node_id, control_plane_epoch, structural_sequence)
        REFERENCES agent_desired_revisions(node_id, control_plane_epoch, structural_sequence)
        ON DELETE RESTRICT
);

CREATE FUNCTION prevent_agent_desired_revision_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'signed desired revisions are immutable';
END;
$$;
CREATE TRIGGER agent_desired_revisions_immutable
    BEFORE UPDATE OR DELETE ON agent_desired_revisions
    FOR EACH ROW EXECUTE FUNCTION prevent_agent_desired_revision_mutation();

CREATE FUNCTION prevent_agent_desired_head_rollback() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'signed desired head deletion requires reviewed epoch recovery';
    END IF;
    IF NEW.node_id IS DISTINCT FROM OLD.node_id
        OR NEW.control_plane_epoch IS DISTINCT FROM OLD.control_plane_epoch
        OR NEW.structural_sequence <= OLD.structural_sequence THEN
        RAISE EXCEPTION 'signed desired head cannot rewind or change epoch';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER agent_desired_head_monotonic
    BEFORE UPDATE OR DELETE ON agent_desired_heads
    FOR EACH ROW EXECUTE FUNCTION prevent_agent_desired_head_rollback();

-- The view's referenced tables and authorization predicates resolve to their
-- bound PostgreSQL objects at CREATE time, including isolated migration-test
-- schemas. The caller needs SELECT on this view, not the underlying tables.
-- A single statement reads a consistent MVCC snapshot of head+binding+org.
CREATE VIEW agent_desired_current WITH (security_barrier=true) AS
SELECT b.node_id::text AS node_id,
       h.control_plane_epoch::text AS control_plane_epoch,
       h.structural_sequence,
       r.membership_sequence,
       r.envelope
FROM agent_desired_heads h
JOIN agent_desired_revisions r
    ON r.node_id=h.node_id
   AND r.control_plane_epoch=h.control_plane_epoch
   AND r.structural_sequence=h.structural_sequence
JOIN agent_grant_node_bindings b ON b.node_id=h.node_id
JOIN agent_grant_organizations org ON org.organization_id=b.organization_id
JOIN nodes n ON n.id=b.legacy_node_id
WHERE b.state='approved'
  AND org.state='active'
  AND n.status IN ('pending_enrollment','active','draining');

-- Public privileges on schema objects are never a gateway authorization grant.
-- Ops must explicitly GRANT only SELECT on the view to the gateway reader role;
-- the issuer, signer, publisher and table owner remain separate principals.
REVOKE ALL ON TABLE agent_desired_revisions, agent_desired_heads, agent_desired_current FROM PUBLIC;

COMMIT;
