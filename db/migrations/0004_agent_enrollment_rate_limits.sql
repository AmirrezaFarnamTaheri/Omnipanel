-- Agent bootstrap admission quotas, using the database clock and shared rows.
-- Only HMAC-SHA256 digests of peer addresses are stored; the HMAC key must
-- be provisioned to all gateways via an external secret manager.
BEGIN;

CREATE TABLE agent_enrollment_rate_windows (
    scope text NOT NULL CHECK (scope IN ('global', 'peer')),
    key_digest bytea NOT NULL CHECK (octet_length(key_digest) = 32),
    window_start bigint NOT NULL CHECK (window_start > 0),
    hits integer NOT NULL CHECK (hits > 0 AND hits <= 1000000),
    PRIMARY KEY (scope, key_digest, window_start)
);

CREATE INDEX agent_enrollment_rate_expiry ON agent_enrollment_rate_windows (window_start);

COMMIT;
