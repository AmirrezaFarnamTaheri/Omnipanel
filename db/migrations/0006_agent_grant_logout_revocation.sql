-- OmniPanel v2: logout-safe enrollment grant revocation (forward-only).
-- Requires migrations 0003 and 0005 plus the legacy admins/admin_sessions.
--
-- Defect: 0005 made agent_grant_issues.session_id a RESTRICT foreign key, so
-- deleting an admin_sessions row (administrator logout) failed whenever any
-- historical issuance metadata referenced that session.
--
-- Fix: record the issuing session's credential hash as an immutable issuance
-- fact, then drop the referential link. Logout can delete the session row;
-- the authorization-aware enrollment store joins admin_sessions by BOTH the
-- recorded id and the recorded token hash, so every outstanding token issued
-- under the deleted session fails closed at lookup and again under the
-- certificate-commit locks. Reusing a deleted session's serial id for a new
-- login cannot resurrect an old bearer because the credential hash differs.
--
-- History is preserved, not rewritten: agent_grant_issues keeps the original
-- session_id/token hash and becomes append-only like agent_grant_audit.
-- Already-issued node certificates are intentionally unaffected by admin
-- logout; online admission keeps depending on the node binding, organization
-- and legacy node status. Step-up rows already cascade on session deletion.
BEGIN;

ALTER TABLE agent_grant_issues ADD COLUMN session_token_hash text;

UPDATE agent_grant_issues i
SET session_token_hash = s.token_hash
FROM admin_sessions s
WHERE s.id = i.session_id;

-- The 0005 RESTRICT foreign key guaranteed every existing issue row still
-- has its session row, so the backfill must cover all rows. If it does not,
-- fail closed instead of recording an unverifiable issuance fact.
ALTER TABLE agent_grant_issues ALTER COLUMN session_token_hash SET NOT NULL;
ALTER TABLE agent_grant_issues ADD CONSTRAINT agent_grant_issues_session_token_hash_format
    CHECK (session_token_hash ~ '^[0-9a-f]{64}$');

ALTER TABLE agent_grant_issues DROP CONSTRAINT agent_grant_issues_session_id_fkey;

CREATE FUNCTION prevent_agent_grant_issue_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'agent grant issuance history is append only';
END;
$$;
CREATE TRIGGER agent_grant_issues_no_update_delete
BEFORE UPDATE OR DELETE ON agent_grant_issues
FOR EACH ROW EXECUTE FUNCTION prevent_agent_grant_issue_mutation();

COMMIT;
