-- OmniPanel initial schema (M1 control-plane foundation).
-- Mirrors src/db/schema.ts. Applied inside a single transaction so the
-- canonical state model is created atomically.

BEGIN;

CREATE TABLE settings (
    key text PRIMARY KEY,
    value text NOT NULL
);

-- ---------- Identity ----------

CREATE TABLE admins (
    id serial PRIMARY KEY,
    email text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    role text NOT NULL DEFAULT 'operator',
    totp_secret_enc text,
    totp_enabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE admin_sessions (
    id serial PRIMARY KEY,
    admin_id integer NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE TABLE audit_log (
    id serial PRIMARY KEY,
    ts timestamptz NOT NULL DEFAULT now(),
    actor text NOT NULL,
    action text NOT NULL,
    object_type text NOT NULL,
    object_id text NOT NULL,
    detail jsonb NOT NULL DEFAULT '{}',
    correlation_id text,
    prev_hash text NOT NULL,
    hash text NOT NULL
);

CREATE TABLE idempotency_records (
    scope text NOT NULL,
    key text NOT NULL,
    request_hash text NOT NULL,
    response jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope, key)
);

-- ---------- Plans & users ----------

CREATE TABLE plans (
    id serial PRIMARY KEY,
    name text NOT NULL UNIQUE,
    quota_bytes bigint,
    enforcement text NOT NULL DEFAULT 'metered',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id serial PRIMARY KEY,
    name text NOT NULL,
    email text,
    plan_id integer NOT NULL REFERENCES plans(id),
    status text NOT NULL DEFAULT 'active',
    suspend_reason text,
    expires_at timestamptz,
    version integer NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE subscription_tokens (
    id serial PRIMARY KEY,
    user_id integer NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    prefix text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    last_used_at timestamptz
);

-- ---------- Infrastructure ----------

CREATE TABLE nodes (
    id serial PRIMARY KEY,
    name text NOT NULL UNIQUE,
    public_address text NOT NULL,
    provider text NOT NULL,
    asn text NOT NULL DEFAULT '',
    region text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'pending_enrollment',
    node_key_hash text,
    last_seen_at timestamptz,
    agent_version text,
    structural_seq integer NOT NULL DEFAULT 0,
    membership_seq integer NOT NULL DEFAULT 0,
    applied_epoch integer,
    applied_structural_seq integer NOT NULL DEFAULT 0,
    applied_membership_seq integer NOT NULL DEFAULT 0,
    applied_state text NOT NULL DEFAULT 'UNKNOWN',
    components jsonb NOT NULL DEFAULT '[]',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE enrollment_tokens (
    id serial PRIMARY KEY,
    node_id integer NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);

CREATE TABLE inbounds (
    id serial PRIMARY KEY,
    node_id integer NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    name text NOT NULL,
    runtime text NOT NULL,
    protocol text NOT NULL,
    transport text NOT NULL,
    port integer NOT NULL,
    sni text NOT NULL,
    params jsonb NOT NULL DEFAULT '{}',
    secrets jsonb NOT NULL DEFAULT '{}',
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT inbounds_listener_uq UNIQUE (node_id, transport, port)
);

CREATE TABLE endpoint_principals (
    id serial PRIMARY KEY,
    user_id integer NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    inbound_id integer NOT NULL REFERENCES inbounds(id) ON DELETE CASCADE,
    attribution_key text NOT NULL UNIQUE,
    credential_enc text NOT NULL,
    state text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);
CREATE UNIQUE INDEX principal_active_uq ON endpoint_principals(user_id, inbound_id)
    WHERE state = 'active';
CREATE INDEX principal_inbound_idx ON endpoint_principals(inbound_id);

-- ---------- Revisions & deployment ----------

CREATE TABLE structural_revisions (
    id serial PRIMARY KEY,
    node_id integer NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    epoch integer NOT NULL,
    sequence integer NOT NULL,
    digest text NOT NULL,
    manifest jsonb NOT NULL,
    disruption text NOT NULL,
    rollback_of integer,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT structural_node_seq_uq UNIQUE (node_id, sequence)
);

CREATE TABLE membership_events (
    id serial PRIMARY KEY,
    node_id integer NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    epoch integer NOT NULL,
    sequence integer NOT NULL,
    type text NOT NULL,
    principal_id integer NOT NULL,
    attribution_key text NOT NULL,
    inbound_id integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT membership_node_seq_uq UNIQUE (node_id, sequence)
);

CREATE TABLE deployment_attempts (
    id serial PRIMARY KEY,
    node_id integer NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    epoch integer,
    structural_seq integer NOT NULL,
    state text NOT NULL,
    components jsonb NOT NULL DEFAULT '[]',
    reported_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE outbox_jobs (
    id serial PRIMARY KEY,
    kind text NOT NULL,
    payload jsonb NOT NULL DEFAULT '{}',
    status text NOT NULL DEFAULT 'pending',
    attempts integer NOT NULL DEFAULT 0,
    run_after timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    done_at timestamptz,
    last_error text
);
CREATE INDEX outbox_status_idx ON outbox_jobs(status, run_after);

-- ---------- Accounting ----------

CREATE TABLE meter_streams (
    id serial PRIMARY KEY,
    node_id integer NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    attribution_key text NOT NULL,
    generation text NOT NULL,
    user_id integer,
    last_seq bigint NOT NULL,
    last_up bigint NOT NULL,
    last_down bigint NOT NULL,
    started_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT meter_stream_uq UNIQUE (node_id, attribution_key, generation)
);

CREATE TABLE meter_observations (
    id serial PRIMARY KEY,
    stream_id integer NOT NULL REFERENCES meter_streams(id) ON DELETE CASCADE,
    seq bigint NOT NULL,
    up bigint NOT NULL,
    down bigint NOT NULL,
    delta_up bigint NOT NULL DEFAULT 0,
    delta_down bigint NOT NULL DEFAULT 0,
    classification text NOT NULL,
    observed_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT meter_obs_uq UNIQUE (stream_id, seq)
);

CREATE TABLE usage_aggregates (
    user_id integer NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bucket timestamptz NOT NULL,
    up bigint NOT NULL DEFAULT 0,
    down bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, bucket)
);

CREATE TABLE usage_quality_intervals (
    id serial PRIMARY KEY,
    user_id integer,
    node_id integer NOT NULL REFERENCES nodes(id),
    kind text NOT NULL,
    note text NOT NULL DEFAULT '',
    detected_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE capability_evidence (
    id serial PRIMARY KEY,
    capability_key text NOT NULL,
    claim text NOT NULL,
    status text NOT NULL,
    note text NOT NULL DEFAULT '',
    recorded_by text NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now()
);

-- ---------- Health & alerts ----------

CREATE TABLE health_observations (
    id serial PRIMARY KEY,
    node_id integer NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    inbound_id integer NOT NULL REFERENCES inbounds(id) ON DELETE CASCADE,
    vantage text NOT NULL,
    level text NOT NULL,
    ok boolean NOT NULL,
    latency_ms integer,
    detail text NOT NULL DEFAULT '',
    observed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX health_inbound_idx ON health_observations(inbound_id, observed_at);

CREATE TABLE inbound_health (
    inbound_id integer PRIMARY KEY REFERENCES inbounds(id) ON DELETE CASCADE,
    state text NOT NULL DEFAULT 'healthy',
    since timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE alerts (
    id serial PRIMARY KEY,
    severity text NOT NULL,
    kind text NOT NULL,
    node_id integer REFERENCES nodes(id),
    message text NOT NULL,
    dedupe_key text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz
);
CREATE UNIQUE INDEX alerts_open_uq ON alerts(dedupe_key) WHERE resolved_at IS NULL;

COMMIT;
