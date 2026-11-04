-- Forward-only trusted TOTP step-up metadata and durable replay/rate controls.
-- Legacy manually written step-up records must NOT silently authorize grants.
-- Requires 0005_agent_admin_grants.sql and legacy admins/admin_sessions.
BEGIN;

ALTER TABLE agent_grant_stepups
  ADD COLUMN verified_counter bigint,
  ADD COLUMN verified_source text NOT NULL DEFAULT 'legacy';

ALTER TABLE agent_grant_stepups
  ADD CONSTRAINT agent_grant_stepups_source_valid
    CHECK (verified_source IN ('legacy', 'trusted')),
  ADD CONSTRAINT agent_grant_stepups_trusted_counter
    CHECK (verified_source <> 'trusted' OR verified_counter >= 0);

CREATE TABLE agent_grant_stepup_counters (
  admin_id integer PRIMARY KEY REFERENCES admins(id) ON DELETE RESTRICT,
  last_counter bigint NOT NULL DEFAULT -1 CHECK (last_counter >= -1),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE agent_grant_stepup_attempts (
  admin_id integer NOT NULL REFERENCES admins(id) ON DELETE RESTRICT,
  window_start bigint NOT NULL CHECK (window_start > 0),
  hits integer NOT NULL CHECK (hits BETWEEN 1 AND 5),
  PRIMARY KEY (admin_id, window_start)
);

CREATE INDEX agent_grant_stepup_attempts_expiry ON agent_grant_stepup_attempts(window_start);
COMMIT;
