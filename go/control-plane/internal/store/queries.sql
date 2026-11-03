-- OmniPanel SQL queries for sqlc code generation.
-- Each named query generates a Go method on the Queries type.

-- Identity
-- name: CreateAdmin :one
INSERT INTO admins (email, password_hash, role, totp_secret_enc, totp_enabled, created_at)
VALUES ($1, $2, $3, $4, $5, now())
RETURNING id, email, password_hash, role, totp_secret_enc, totp_enabled, created_at;

-- name: GetAdminByEmail :one
SELECT id, email, password_hash, role, totp_secret_enc, totp_enabled, created_at
FROM admins
WHERE email = $1;

-- name: CreateAdminSession :one
INSERT INTO admin_sessions (admin_id, token_hash, expires_at)
VALUES ($1, $2, $3)
RETURNING id, admin_id, token_hash, created_at, last_seen_at, expires_at;

-- name: GetSessionByToken :one
SELECT id, admin_id, token_hash, created_at, last_seen_at, expires_at
FROM admin_sessions
WHERE token_hash = $1;

-- name: UpdateSessionLastSeen :exec
UPDATE admin_sessions
SET last_seen_at = now()
WHERE id = $1;

-- name: DeleteSession :exec
DELETE FROM admin_sessions
WHERE id = $1;

-- name: DeleteSessionsForAdmin :exec
DELETE FROM admin_sessions
WHERE admin_id = $1;

-- name: InsertAuditLog :exec
INSERT INTO audit_log (actor, action, object_type, object_id, detail, correlation_id, prev_hash, hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- Plans
-- name: CreatePlan :one
INSERT INTO plans (name, quota_bytes, enforcement, created_at)
VALUES ($1, $2, $3, now())
RETURNING id, name, quota_bytes, enforcement, created_at;

-- name: ListPlans :many
SELECT id, name, quota_bytes, enforcement, created_at
FROM plans
ORDER BY id;

-- name: GetPlan :one
SELECT id, name, quota_bytes, enforcement, created_at
FROM plans
WHERE id = $1;

-- Users
-- name: CreateUser :one
INSERT INTO users (name, email, plan_id, status, version, created_at, updated_at)
VALUES ($1, $2, $3, 'active', 1, now(), now())
RETURNING id, name, email, plan_id, status, suspend_reason, expires_at, version, created_at, updated_at;

-- name: GetUser :one
SELECT id, name, email, plan_id, status, suspend_reason, expires_at, version, created_at, updated_at
FROM users
WHERE id = $1;

-- name: ListUsers :many
SELECT id, name, email, plan_id, status, suspend_reason, expires_at, version, created_at, updated_at
FROM users
ORDER BY id;

-- name: UpdateUserStatus :exec
UPDATE users
SET status = $2, suspend_reason = $3, updated_at = now(), version = version + 1
WHERE id = $1;

-- name: CreateSubscriptionToken :one
INSERT INTO subscription_tokens (user_id, token_hash, prefix, created_at)
VALUES ($1, $2, $3, now())
RETURNING id, user_id, token_hash, prefix, created_at, revoked_at, last_used_at;

-- name: GetUserByToken :one
SELECT u.id, u.name, u.email, u.plan_id, u.status, u.suspend_reason, u.expires_at, u.version, u.created_at, u.updated_at
FROM users u
JOIN subscription_tokens st ON st.user_id = u.id
WHERE st.token_hash = $1 AND st.revoked_at IS NULL;

-- Infrastructure
-- name: CreateNode :one
INSERT INTO nodes (name, public_address, provider, asn, region, status, created_at)
VALUES ($1, $2, $3, $4, $5, 'pending_enrollment', now())
RETURNING id, name, public_address, provider, asn, region, status, node_key_hash, last_seen_at, agent_version, structural_seq, membership_seq, applied_epoch, applied_structural_seq, applied_membership_seq, applied_state, components, created_at;

-- name: GetNode :one
SELECT id, name, public_address, provider, asn, region, status, node_key_hash, last_seen_at, agent_version, structural_seq, membership_seq, applied_epoch, applied_structural_seq, applied_membership_seq, applied_state, components, created_at
FROM nodes
WHERE id = $1;

-- name: ListNodes :many
SELECT id, name, public_address, provider, asn, region, status, node_key_hash, last_seen_at, agent_version, structural_seq, membership_seq, applied_epoch, applied_structural_seq, applied_membership_seq, applied_state, components, created_at
FROM nodes
ORDER BY id;

-- name: UpdateNodeAddress :one
UPDATE nodes
SET public_address = $2, updated_at = now()
WHERE id = $1
RETURNING id, name, public_address, provider, asn, region, status, node_key_hash, last_seen_at, agent_version, structural_seq, membership_seq, applied_epoch, applied_structural_seq, applied_membership_seq, applied_state, components, created_at;

-- name: CreateEnrollmentToken :one
INSERT INTO enrollment_tokens (node_id, token_hash, expires_at)
VALUES ($1, $2, $3)
RETURNING id, node_id, token_hash, expires_at, used_at;

-- name: GetEnrollmentToken :one
SELECT id, node_id, token_hash, expires_at, used_at
FROM enrollment_tokens
WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now();

-- name: MarkEnrollmentTokenUsed :exec
UPDATE enrollment_tokens
SET used_at = now()
WHERE id = $1;

-- name: SetNodeKeyHash :exec
UPDATE nodes
SET node_key_hash = $2, status = 'active', last_seen_at = now()
WHERE id = $1;

-- name: QuarantineNode :exec
UPDATE nodes
SET status = 'quarantined', node_key_hash = NULL
WHERE id = $1;

-- name: CreateInbound :one
INSERT INTO inbounds (node_id, name, runtime, protocol, transport, port, sni, params, secrets, enabled, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())
RETURNING id, node_id, name, runtime, protocol, transport, port, sni, params, secrets, enabled, created_at;

-- name: ListInboundsByNode :many
SELECT id, node_id, name, runtime, protocol, transport, port, sni, params, secrets, enabled, created_at
FROM inbounds
WHERE node_id = $1
ORDER BY id;

-- name: SetInboundEnabled :exec
UPDATE inbounds
SET enabled = $2
WHERE id = $1;

-- name: CreateEndpointPrincipal :one
INSERT INTO endpoint_principals (user_id, inbound_id, attribution_key, credential_enc, state, created_at)
VALUES ($1, $2, $3, $4, 'active', now())
RETURNING id, user_id, inbound_id, attribution_key, credential_enc, state, created_at, revoked_at;

-- name: GetEndpointPrincipalByAttributionKey :one
SELECT id, user_id, inbound_id, attribution_key, credential_enc, state, created_at, revoked_at
FROM endpoint_principals
WHERE attribution_key = $1 AND state = 'active';

-- name: RevokeEndpointPrincipal :exec
UPDATE endpoint_principals
SET state = 'revoked', revoked_at = now()
WHERE id = $1;

-- Revisions
-- name: PublishStructuralRevision :one
INSERT INTO structural_revisions (node_id, epoch, sequence, digest, manifest, disruption, rollback_of, created_by, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
RETURNING id, node_id, epoch, sequence, digest, manifest, disruption, rollback_of, created_by, created_at;

-- name: GetLatestStructuralSeq :one
SELECT COALESCE(MAX(sequence), 0)
FROM structural_revisions
WHERE node_id = $1;

-- name: CreateMembershipEvent :one
INSERT INTO membership_events (node_id, epoch, sequence, type, principal_id, attribution_key, inbound_id, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, now())
RETURNING id, node_id, epoch, sequence, type, principal_id, attribution_key, inbound_id, created_at;

-- name: GetLatestMembershipSeq :one
SELECT COALESCE(MAX(sequence), 0)
FROM membership_events
WHERE node_id = $1;

-- name: CreateDeploymentAttempt :one
INSERT INTO deployment_attempts (node_id, epoch, structural_seq, state, components, reported_at)
VALUES ($1, $2, $3, $4, $5, now())
RETURNING id, node_id, epoch, structural_seq, state, components, reported_at;

-- Outbox
-- name: CreateOutboxJob :one
INSERT INTO outbox_jobs (kind, payload, status, attempts, run_after, created_at)
VALUES ($1, $2, 'pending', 0, now(), now())
RETURNING id, kind, payload, status, attempts, run_after, created_at, done_at, last_error;

-- name: ClaimOutboxJob :one
SELECT id, kind, payload, status, attempts, run_after, created_at, done_at, last_error
FROM outbox_jobs
WHERE status = 'pending' AND run_after <= now()
ORDER BY id
LIMIT 1;

-- name: MarkOutboxJobDone :exec
UPDATE outbox_jobs
SET status = 'done', done_at = now(), attempts = attempts + 1
WHERE id = $1;

-- name: MarkOutboxJobFailed :exec
UPDATE outbox_jobs
SET attempts = attempts + 1,
    status = CASE WHEN attempts + 1 >= 5 THEN 'failed' ELSE 'pending' END,
    run_after = now() + (interval '30 seconds' * (attempts + 1)),
    last_error = $2
WHERE id = $1;

-- Accounting
-- name: CreateMeterStream :one
INSERT INTO meter_streams (node_id, attribution_key, generation, user_id, last_seq, last_up, last_down, started_at, updated_at)
VALUES ($1, $2, $3, $4, 0, 0, 0, now(), now())
RETURNING id, node_id, attribution_key, generation, user_id, last_seq, last_up, last_down, started_at, updated_at;

-- name: GetMeterStream :one
SELECT id, node_id, attribution_key, generation, user_id, last_seq, last_up, last_down, started_at, updated_at
FROM meter_streams
WHERE node_id = $1 AND attribution_key = $2 AND generation = $3;

-- name: UpsertMeterStream :exec
INSERT INTO meter_streams (node_id, attribution_key, generation, user_id, last_seq, last_up, last_down, started_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())
ON CONFLICT (node_id, attribution_key, generation)
DO UPDATE SET last_seq = $5, last_up = $6, last_down = $7, updated_at = now();

-- name: InsertMeterObservation :one
INSERT INTO meter_observations (stream_id, seq, up, down, delta_up, delta_down, classification, observed_at, received_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
RETURNING id, stream_id, seq, up, down, delta_up, delta_down, classification, observed_at, received_at;

-- name: InsertUsageAggregate :exec
INSERT INTO usage_aggregates (user_id, bucket, up, down)
VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id, bucket)
DO UPDATE SET up = usage_aggregates.up + EXCLUDED.up, down = usage_aggregates.down + EXCLUDED.down;

-- name: InsertUsageQualityInterval :exec
INSERT INTO usage_quality_intervals (user_id, node_id, kind, note, detected_at)
VALUES ($1, $2, $3, $4, now());

-- Health
-- name: InsertHealthObservation :exec
INSERT INTO health_observations (node_id, inbound_id, vantage, level, ok, latency_ms, detail, observed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, now());

-- name: UpsertInboundHealth :exec
INSERT INTO inbound_health (inbound_id, state, since, updated_at)
VALUES ($1, $2, now(), now())
ON CONFLICT (inbound_id)
DO UPDATE SET state = EXCLUDED.state, updated_at = now();

-- name: CreateAlert :exec
INSERT INTO alerts (severity, kind, node_id, message, dedupe_key, created_at)
VALUES ($1, $2, $3, $4, $5, now());
