-- OmniPanel v2 node enrollment credential ledger (PostgreSQL).
-- Applied only as part of a reviewed control-plane migration. This does not
-- provision a CA, expose an enrollment route, or authorize a node by itself.
BEGIN;

CREATE TABLE agent_enrollment_grants (
    token_digest bytea PRIMARY KEY CHECK(octet_length(token_digest) = 32),
    node_id text NOT NULL CHECK(node_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    expires_at bigint NOT NULL,
    created_at bigint NOT NULL,
    consumed_at bigint,
    CHECK(expires_at > created_at)
);

CREATE INDEX agent_enrollment_pending ON agent_enrollment_grants(node_id, expires_at)
    WHERE consumed_at IS NULL;

CREATE TABLE agent_node_certificates (
    serial text PRIMARY KEY,
    node_id text NOT NULL CHECK(node_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}
    spki_digest bytea NOT NULL CHECK(octet_length(spki_digest) = 32),
    not_before bigint NOT NULL,
    not_after bigint NOT NULL,
    issued_at bigint NOT NULL,
    revoked_at bigint,
    CHECK(not_after > not_before)
);

CREATE INDEX agent_certificates_active ON agent_node_certificates(node_id, not_after)
    WHERE revoked_at IS NULL;

COMMIT;
),
    spki_digest bytea NOT NULL CHECK(octet_length(spki_digest) = 32),
    not_before bigint NOT NULL,
    not_after bigint NOT NULL,
    issued_at bigint NOT NULL,
    revoked_at bigint,
    CHECK(not_after > not_before)
);

CREATE INDEX agent_certificates_active ON agent_node_certificates(node_id, not_after)
    WHERE revoked_at IS NULL;

COMMIT;
