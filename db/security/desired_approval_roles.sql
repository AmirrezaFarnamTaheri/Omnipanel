-- Optional DBA provisioning for OmniPanel's isolated administrator approval service.
-- Apply ONLY after migrations 0001-0010 to a dedicated database. Not an automatic migration.
-- The three LOGIN roles are provisioned and rotated separately. No secrets here.
BEGIN;
SET LOCAL search_path=pg_catalog,public;
DO $verify$
DECLARE role_name text; role_oid oid;
BEGIN
 FOREACH role_name IN ARRAY ARRAY['omni_desired_session','omni_desired_proposer','omni_desired_reviewer'] LOOP
  SELECT oid INTO role_oid FROM pg_catalog.pg_roles WHERE rolname=role_name
   AND rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole
   AND NOT rolreplication AND NOT rolbypassrls;
  IF role_oid IS NULL THEN RAISE EXCEPTION 'missing/unsafe administrator role %',role_name; END IF;
  IF EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=role_oid) THEN
   RAISE EXCEPTION 'administrator role % has memberships',role_name;
  END IF;
  IF pg_catalog.has_schema_privilege(role_name,'public','CREATE') OR
   pg_catalog.has_database_privilege(role_name,pg_catalog.current_database(),'CREATE') THEN
   RAISE EXCEPTION 'administrator role % has DDL rights',role_name;
  END IF;
  IF EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n
   ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relowner=role_oid) THEN
   RAISE EXCEPTION 'administrator role % owns database objects',role_name;
  END IF;
  IF EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n
    ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f')
    AND (pg_catalog.has_any_column_privilege(role_name,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')
      OR pg_catalog.has_table_privilege(role_name,c.oid,'DELETE,TRUNCATE,TRIGGER')))
   OR EXISTS(SELECT 1 FROM pg_catalog.pg_sequences seq
     WHERE seq.schemaname='public' AND pg_catalog.has_sequence_privilege(role_name,
       pg_catalog.format('%I.%I',seq.schemaname,seq.sequencename),'USAGE,SELECT,UPDATE')) THEN
   RAISE EXCEPTION 'administrator role % has preexisting privileges',role_name;
  END IF;
 END LOOP;
END;
$verify$;
GRANT USAGE ON SCHEMA public TO omni_desired_session,omni_desired_proposer,omni_desired_reviewer;
GRANT SELECT(id,role,totp_enabled) ON public.admins
 TO omni_desired_session,omni_desired_proposer,omni_desired_reviewer;
GRANT SELECT(id,admin_id,token_hash,created_at,last_seen_at,expires_at) ON public.admin_sessions
 TO omni_desired_session,omni_desired_proposer,omni_desired_reviewer;
GRANT SELECT(admin_id,organization_id,can_propose,can_approve) ON public.agent_desired_publish_permissions
 TO omni_desired_proposer,omni_desired_reviewer;
GRANT SELECT(session_id,method,verified_at,expires_at,verified_source,verified_counter)
 ON public.agent_grant_stepups TO omni_desired_proposer,omni_desired_reviewer;
GRANT SELECT(node_id,organization_id,legacy_node_id,state,approved_at)
 ON public.agent_grant_node_bindings TO omni_desired_proposer,omni_desired_reviewer;
GRANT SELECT(organization_id,state) ON public.agent_grant_organizations
 TO omni_desired_proposer,omni_desired_reviewer;
GRANT SELECT(id,status) ON public.nodes TO omni_desired_proposer,omni_desired_reviewer;

-- FOR SHARE/FOR UPDATE need UPDATE privilege on at least one column.
-- This trigger denies any actual mutation from runtime login sessions.
CREATE FUNCTION public.omni_deny_runtime_lockonly_updates() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog AS $deny$
BEGIN
 IF session_user IN ('omni_desired_proposer','omni_desired_reviewer') THEN
  RAISE EXCEPTION 'row-lock permission cannot mutate authorization data' USING ERRCODE='42501';
 END IF;
 RETURN NEW;
END;
$deny$;
REVOKE ALL ON FUNCTION public.omni_deny_runtime_lockonly_updates() FROM PUBLIC;
CREATE TRIGGER omni_runtime_lockonly_update_deny BEFORE UPDATE ON public.admins
 FOR EACH ROW EXECUTE FUNCTION public.omni_deny_runtime_lockonly_updates();
CREATE TRIGGER omni_runtime_lockonly_update_deny BEFORE UPDATE ON public.admin_sessions
 FOR EACH ROW EXECUTE FUNCTION public.omni_deny_runtime_lockonly_updates();
CREATE TRIGGER omni_runtime_lockonly_update_deny BEFORE UPDATE ON public.agent_desired_publish_permissions
 FOR EACH ROW EXECUTE FUNCTION public.omni_deny_runtime_lockonly_updates();
CREATE TRIGGER omni_runtime_lockonly_update_deny BEFORE UPDATE ON public.agent_grant_stepups
 FOR EACH ROW EXECUTE FUNCTION public.omni_deny_runtime_lockonly_updates();
CREATE TRIGGER omni_runtime_lockonly_update_deny BEFORE UPDATE ON public.agent_grant_node_bindings
 FOR EACH ROW EXECUTE FUNCTION public.omni_deny_runtime_lockonly_updates();
CREATE TRIGGER omni_runtime_lockonly_update_deny BEFORE UPDATE ON public.agent_grant_organizations
 FOR EACH ROW EXECUTE FUNCTION public.omni_deny_runtime_lockonly_updates();
CREATE TRIGGER omni_runtime_lockonly_update_deny BEFORE UPDATE ON public.nodes
 FOR EACH ROW EXECUTE FUNCTION public.omni_deny_runtime_lockonly_updates();
GRANT UPDATE(id) ON public.admins,public.admin_sessions,public.nodes
 TO omni_desired_proposer,omni_desired_reviewer;
GRANT UPDATE(admin_id) ON public.agent_desired_publish_permissions
 TO omni_desired_proposer,omni_desired_reviewer;
GRANT UPDATE(session_id) ON public.agent_grant_stepups
 TO omni_desired_proposer,omni_desired_reviewer;
GRANT UPDATE(node_id) ON public.agent_grant_node_bindings
 TO omni_desired_proposer,omni_desired_reviewer;
GRANT UPDATE(organization_id) ON public.agent_grant_organizations
 TO omni_desired_proposer,omni_desired_reviewer;
GRANT INSERT(proposal_id,organization_id,node_id,control_plane_epoch,
 structural_sequence,membership_sequence,envelope_sha256,envelope,proposer_admin_id,
 proposer_session_id,proposer_session_hash,proposer_stepup_counter,created_at,expires_at)
 ON public.agent_desired_publish_proposals TO omni_desired_proposer;
GRANT SELECT(proposal_id,organization_id,node_id,control_plane_epoch,structural_sequence,
 membership_sequence,envelope_sha256,envelope,proposer_admin_id,proposer_session_id,
 proposer_session_hash,proposer_stepup_counter,expires_at,created_at)
 ON public.agent_desired_publish_proposals TO omni_desired_reviewer;
-- PostgreSQL requires UPDATE privilege to lock rows FOR UPDATE.
-- The migration's row-level immutability trigger cannot reject UPDATE statements
-- affecting zero rows. A statement-level guard ensures this lock-only grant
-- cannot be used to issue any proposal UPDATE, even on an empty table.
CREATE TRIGGER omni_runtime_immutable_proposal_update_deny
 BEFORE UPDATE ON public.agent_desired_publish_proposals
 FOR EACH STATEMENT EXECUTE FUNCTION public.omni_deny_runtime_lockonly_updates();
GRANT UPDATE(proposal_id) ON public.agent_desired_publish_proposals TO omni_desired_reviewer;
GRANT SELECT(proposal_id) ON public.agent_desired_publish_decisions TO omni_desired_reviewer;
GRANT INSERT(approval_id,organization_id,node_id,control_plane_epoch,
 structural_sequence,membership_sequence,envelope_sha256,issuer_admin_id,
 approver_admin_id,created_at,expires_at)
 ON public.agent_desired_publish_approvals TO omni_desired_reviewer;
GRANT INSERT(proposal_id,approval_id,approver_admin_id,approver_session_id,
 approver_session_hash,approver_stepup_counter,reviewed_sha256,approved_at)
 ON public.agent_desired_publish_decisions TO omni_desired_reviewer;
DO $path$
DECLARE role_name text;
BEGIN
 FOREACH role_name IN ARRAY ARRAY['omni_desired_session','omni_desired_proposer','omni_desired_reviewer'] LOOP
  EXECUTE pg_catalog.format('ALTER ROLE %I IN DATABASE %I SET search_path = pg_catalog, public',
   role_name,pg_catalog.current_database());
 END LOOP;
END;
$path$;
COMMIT;
