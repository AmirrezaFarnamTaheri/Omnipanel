-- OmniPanel v2: two-stage, session-bound, dual-operator desired publication approvals.
-- Requires 0001-0009; no HTTP endpoints or production role GRANTs are deployed.
BEGIN;

-- An immutable proposal is an authenticated owner's exact signed intent.
-- Its evidence is bound to a real administrator session credential hash and a
-- recent independently verified TOTP counter, never a request-supplied flag.
CREATE TABLE agent_desired_publish_proposals (
    proposal_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES agent_grant_organizations(organization_id) ON DELETE RESTRICT,
    node_id uuid NOT NULL,
    control_plane_epoch uuid NOT NULL,
    structural_sequence bigint NOT NULL CHECK (structural_sequence BETWEEN 1 AND 9007199254740991),
    membership_sequence bigint NOT NULL CHECK (membership_sequence BETWEEN 0 AND 9007199254740991),
    envelope_sha256 bytea NOT NULL CHECK (octet_length(envelope_sha256) = 32),
    envelope bytea NOT NULL CHECK (octet_length(envelope) BETWEEN 1 AND 1048576),
    proposer_admin_id integer NOT NULL REFERENCES admins(id) ON DELETE RESTRICT,
    proposer_session_id integer NOT NULL,
    proposer_session_hash text NOT NULL CHECK (proposer_session_hash ~ '^[0-9a-f]{64}$'),
    proposer_stepup_counter bigint NOT NULL CHECK (proposer_stepup_counter >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
    FOREIGN KEY (node_id, organization_id)
        REFERENCES agent_grant_node_bindings(node_id, organization_id) ON DELETE RESTRICT
);

-- Only a separate authenticated owner can approve an immutable proposal.
-- Storing the second session credential hash prevents recycled session IDs or
-- a logout from resurrecting an old authorization.
CREATE TABLE agent_desired_publish_decisions (
    proposal_id uuid PRIMARY KEY REFERENCES agent_desired_publish_proposals(proposal_id) ON DELETE RESTRICT,
    approval_id uuid NOT NULL UNIQUE REFERENCES agent_desired_publish_approvals(approval_id) ON DELETE RESTRICT,
    approver_admin_id integer NOT NULL REFERENCES admins(id) ON DELETE RESTRICT,
    approver_session_id integer NOT NULL,
    approver_session_hash text NOT NULL CHECK (approver_session_hash ~ '^[0-9a-f]{64}$'),
    approver_stepup_counter bigint NOT NULL CHECK (approver_stepup_counter >= 0),
    reviewed_sha256 bytea NOT NULL CHECK (octet_length(reviewed_sha256) = 32),
    approved_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TRIGGER agent_desired_publish_proposals_immutable
    BEFORE UPDATE OR DELETE ON agent_desired_publish_proposals
    FOR EACH ROW EXECUTE FUNCTION prevent_agent_desired_publication_history_mutation();
CREATE TRIGGER agent_desired_publish_decisions_immutable
    BEFORE UPDATE OR DELETE ON agent_desired_publish_decisions
    FOR EACH ROW EXECUTE FUNCTION prevent_agent_desired_publication_history_mutation();

CREATE INDEX agent_desired_publish_proposals_expiry
    ON agent_desired_publish_proposals(node_id, expires_at DESC);

REVOKE ALL ON TABLE agent_desired_publish_proposals,
    agent_desired_publish_decisions FROM PUBLIC;

COMMIT;
