import {
  bigint,
  boolean,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  serial,
  text,
  timestamp,
  uniqueIndex,
} from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";

const ts = (name: string) => timestamp(name, { withTimezone: true });
const bytes = (name: string) => bigint(name, { mode: "number" });

export const settings = pgTable("settings", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
});

/* ---------- Identity ---------- */

export const admins = pgTable("admins", {
  id: serial("id").primaryKey(),
  email: text("email").notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  role: text("role").notNull().default("operator"), // owner | operator | viewer
  totpSecretEnc: text("totp_secret_enc"),
  totpEnabled: boolean("totp_enabled").notNull().default(false),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const adminSessions = pgTable("admin_sessions", {
  id: serial("id").primaryKey(),
  adminId: integer("admin_id").notNull().references(() => admins.id, { onDelete: "cascade" }),
  tokenHash: text("token_hash").notNull().unique(),
  createdAt: ts("created_at").notNull().defaultNow(),
  lastSeenAt: ts("last_seen_at").notNull().defaultNow(),
  expiresAt: ts("expires_at").notNull(),
});

export const auditLog = pgTable("audit_log", {
  id: serial("id").primaryKey(),
  ts: ts("ts").notNull().defaultNow(),
  actor: text("actor").notNull(),
  action: text("action").notNull(),
  objectType: text("object_type").notNull(),
  objectId: text("object_id").notNull(),
  detail: jsonb("detail").$type<Record<string, unknown>>().notNull().default({}),
  correlationId: text("correlation_id"),
  prevHash: text("prev_hash").notNull(),
  hash: text("hash").notNull(),
});

export const idempotencyRecords = pgTable(
  "idempotency_records",
  {
    scope: text("scope").notNull(),
    key: text("key").notNull(),
    requestHash: text("request_hash").notNull(),
    response: jsonb("response").$type<unknown>(),
    createdAt: ts("created_at").notNull().defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.scope, t.key] })],
);

/* ---------- Plans & users ---------- */

export const plans = pgTable("plans", {
  id: serial("id").primaryKey(),
  name: text("name").notNull().unique(),
  quotaBytes: bytes("quota_bytes"),
  enforcement: text("enforcement").notNull().default("metered"), // hard | metered | unmetered
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email"),
  planId: integer("plan_id").notNull().references(() => plans.id),
  status: text("status").notNull().default("active"), // active | suspended | expired
  suspendReason: text("suspend_reason"),
  expiresAt: ts("expires_at"),
  version: integer("version").notNull().default(1),
  createdAt: ts("created_at").notNull().defaultNow(),
  updatedAt: ts("updated_at").notNull().defaultNow(),
});

export const subscriptionTokens = pgTable("subscription_tokens", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  tokenHash: text("token_hash").notNull().unique(),
  prefix: text("prefix").notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
  revokedAt: ts("revoked_at"),
  lastUsedAt: ts("last_used_at"),
});

/* ---------- Infrastructure ---------- */

export const nodes = pgTable("nodes", {
  id: serial("id").primaryKey(),
  name: text("name").notNull().unique(),
  publicAddress: text("public_address").notNull(),
  provider: text("provider").notNull(),
  asn: text("asn").notNull().default(""),
  region: text("region").notNull().default(""),
  status: text("status").notNull().default("pending_enrollment"), // pending_enrollment | active | draining | quarantined
  nodeKeyHash: text("node_key_hash"),
  lastSeenAt: ts("last_seen_at"),
  agentVersion: text("agent_version"),
  structuralSeq: integer("structural_seq").notNull().default(0),
  membershipSeq: integer("membership_seq").notNull().default(0),
  appliedEpoch: integer("applied_epoch"),
  appliedStructuralSeq: integer("applied_structural_seq").notNull().default(0),
  appliedMembershipSeq: integer("applied_membership_seq").notNull().default(0),
  appliedState: text("applied_state").notNull().default("UNKNOWN"),
  components: jsonb("components").$type<Array<{ name: string; state: string; detail?: string }>>().notNull().default([]),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const enrollmentTokens = pgTable("enrollment_tokens", {
  id: serial("id").primaryKey(),
  nodeId: integer("node_id").notNull().references(() => nodes.id, { onDelete: "cascade" }),
  tokenHash: text("token_hash").notNull().unique(),
  expiresAt: ts("expires_at").notNull(),
  usedAt: ts("used_at"),
});

export const inbounds = pgTable(
  "inbounds",
  {
    id: serial("id").primaryKey(),
    nodeId: integer("node_id").notNull().references(() => nodes.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    runtime: text("runtime").notNull(), // singbox | xray | hysteria2
    protocol: text("protocol").notNull(), // vless-reality-vision | hysteria2
    transport: text("transport").notNull(), // tcp | udp
    port: integer("port").notNull(),
    sni: text("sni").notNull(),
    params: jsonb("params").$type<Record<string, string>>().notNull().default({}),
    secrets: jsonb("secrets").$type<Record<string, string>>().notNull().default({}), // encrypted values
    enabled: boolean("enabled").notNull().default(true),
    createdAt: ts("created_at").notNull().defaultNow(),
  },
  (t) => [uniqueIndex("inbounds_listener_uq").on(t.nodeId, t.transport, t.port)],
);

export const endpointPrincipals = pgTable(
  "endpoint_principals",
  {
    id: serial("id").primaryKey(),
    userId: integer("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    inboundId: integer("inbound_id").notNull().references(() => inbounds.id, { onDelete: "cascade" }),
    attributionKey: text("attribution_key").notNull().unique(),
    credentialEnc: text("credential_enc").notNull(),
    state: text("state").notNull().default("active"), // active | revoked
    createdAt: ts("created_at").notNull().defaultNow(),
    revokedAt: ts("revoked_at"),
  },
  (t) => [
    uniqueIndex("principal_active_uq").on(t.userId, t.inboundId).where(sql`state = 'active'`),
    index("principal_inbound_idx").on(t.inboundId),
  ],
);

/* ---------- Revisions & deployment ---------- */

export const structuralRevisions = pgTable(
  "structural_revisions",
  {
    id: serial("id").primaryKey(),
    nodeId: integer("node_id").notNull().references(() => nodes.id, { onDelete: "cascade" }),
    epoch: integer("epoch").notNull(),
    sequence: integer("sequence").notNull(),
    digest: text("digest").notNull(),
    manifest: jsonb("manifest").$type<Record<string, unknown>>().notNull(),
    disruption: text("disruption").notNull(),
    rollbackOf: integer("rollback_of"),
    createdBy: text("created_by").notNull(),
    createdAt: ts("created_at").notNull().defaultNow(),
  },
  (t) => [uniqueIndex("structural_node_seq_uq").on(t.nodeId, t.sequence)],
);

export const membershipEvents = pgTable(
  "membership_events",
  {
    id: serial("id").primaryKey(),
    nodeId: integer("node_id").notNull().references(() => nodes.id, { onDelete: "cascade" }),
    epoch: integer("epoch").notNull(),
    sequence: integer("sequence").notNull(),
    type: text("type").notNull(), // add | remove | suspend | resume
    principalId: integer("principal_id").notNull(),
    attributionKey: text("attribution_key").notNull(),
    inboundId: integer("inbound_id").notNull(),
    createdAt: ts("created_at").notNull().defaultNow(),
  },
  (t) => [uniqueIndex("membership_node_seq_uq").on(t.nodeId, t.sequence)],
);

export const deploymentAttempts = pgTable("deployment_attempts", {
  id: serial("id").primaryKey(),
  nodeId: integer("node_id").notNull().references(() => nodes.id, { onDelete: "cascade" }),
  epoch: integer("epoch"),
  structuralSeq: integer("structural_seq").notNull(),
  state: text("state").notNull(),
  components: jsonb("components").$type<Array<{ name: string; state: string; detail?: string }>>().notNull().default([]),
  reportedAt: ts("reported_at").notNull().defaultNow(),
});

export const outboxJobs = pgTable(
  "outbox_jobs",
  {
    id: serial("id").primaryKey(),
    kind: text("kind").notNull(),
    payload: jsonb("payload").$type<Record<string, unknown>>().notNull().default({}),
    status: text("status").notNull().default("pending"), // pending | done | failed
    attempts: integer("attempts").notNull().default(0),
    runAfter: ts("run_after").notNull().defaultNow(),
    createdAt: ts("created_at").notNull().defaultNow(),
    doneAt: ts("done_at"),
    lastError: text("last_error"),
  },
  (t) => [index("outbox_status_idx").on(t.status, t.runAfter)],
);

/* ---------- Accounting ---------- */

export const meterStreams = pgTable(
  "meter_streams",
  {
    id: serial("id").primaryKey(),
    nodeId: integer("node_id").notNull().references(() => nodes.id, { onDelete: "cascade" }),
    attributionKey: text("attribution_key").notNull(),
    generation: text("generation").notNull(),
    userId: integer("user_id"),
    lastSeq: bigint("last_seq", { mode: "number" }).notNull(),
    lastUp: bytes("last_up").notNull(),
    lastDown: bytes("last_down").notNull(),
    startedAt: ts("started_at").notNull().defaultNow(),
    updatedAt: ts("updated_at").notNull().defaultNow(),
  },
  (t) => [uniqueIndex("meter_stream_uq").on(t.nodeId, t.attributionKey, t.generation)],
);

export const meterObservations = pgTable(
  "meter_observations",
  {
    id: serial("id").primaryKey(),
    streamId: integer("stream_id").notNull().references(() => meterStreams.id, { onDelete: "cascade" }),
    seq: bigint("seq", { mode: "number" }).notNull(),
    up: bytes("up").notNull(),
    down: bytes("down").notNull(),
    deltaUp: bytes("delta_up").notNull().default(0),
    deltaDown: bytes("delta_down").notNull().default(0),
    classification: text("classification").notNull(),
    observedAt: ts("observed_at").notNull(),
    receivedAt: ts("received_at").notNull().defaultNow(),
  },
  (t) => [uniqueIndex("meter_obs_uq").on(t.streamId, t.seq)],
);

export const usageAggregates = pgTable(
  "usage_aggregates",
  {
    userId: integer("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    bucket: ts("bucket").notNull(),
    up: bytes("up").notNull().default(0),
    down: bytes("down").notNull().default(0),
  },
  (t) => [primaryKey({ columns: [t.userId, t.bucket] })],
);

export const usageQualityIntervals = pgTable("usage_quality_intervals", {
  id: serial("id").primaryKey(),
  userId: integer("user_id"),
  nodeId: integer("node_id").notNull(),
  kind: text("kind").notNull(), // counter_reset | missing_baseline | conflict | agent_overflow
  note: text("note").notNull().default(""),
  detectedAt: ts("detected_at").notNull().defaultNow(),
});

export const capabilityEvidence = pgTable("capability_evidence", {
  id: serial("id").primaryKey(),
  capabilityKey: text("capability_key").notNull(),
  claim: text("claim").notNull(), // admission | metering | revocation | hardQuota
  status: text("status").notNull(), // verified | failed
  note: text("note").notNull().default(""),
  recordedBy: text("recorded_by").notNull(),
  recordedAt: ts("recorded_at").notNull().defaultNow(),
});

/* ---------- Health & alerts ---------- */

export const healthObservations = pgTable(
  "health_observations",
  {
    id: serial("id").primaryKey(),
    nodeId: integer("node_id").notNull().references(() => nodes.id, { onDelete: "cascade" }),
    inboundId: integer("inbound_id").notNull().references(() => inbounds.id, { onDelete: "cascade" }),
    vantage: text("vantage").notNull(),
    level: text("level").notNull(), // L0 | L1 | L2 | L3
    ok: boolean("ok").notNull(),
    latencyMs: integer("latency_ms"),
    detail: text("detail").notNull().default(""),
    observedAt: ts("observed_at").notNull().defaultNow(),
  },
  (t) => [index("health_inbound_idx").on(t.inboundId, t.observedAt)],
);

export const inboundHealth = pgTable("inbound_health", {
  inboundId: integer("inbound_id").primaryKey().references(() => inbounds.id, { onDelete: "cascade" }),
  state: text("state").notNull().default("healthy"),
  since: ts("since").notNull().defaultNow(),
  updatedAt: ts("updated_at").notNull().defaultNow(),
});

export const alerts = pgTable(
  "alerts",
  {
    id: serial("id").primaryKey(),
    severity: text("severity").notNull(), // critical | warning | info
    kind: text("kind").notNull(),
    nodeId: integer("node_id"),
    message: text("message").notNull(),
    dedupeKey: text("dedupe_key").notNull(),
    createdAt: ts("created_at").notNull().defaultNow(),
    resolvedAt: ts("resolved_at"),
  },
  (t) => [uniqueIndex("alerts_open_uq").on(t.dedupeKey).where(sql`resolved_at is null`)],
);

/* ---------- M2: Integrated platform ---------- */

export const cdnMappings = pgTable(
  "cdn_mappings",
  {
    id: serial("id").primaryKey(),
    domain: text("domain").notNull().unique(),
    origin: text("origin").notNull(),
    provider: text("provider").notNull(),
    status: text("status").notNull().default("pending"),
    createdAt: ts("created_at").notNull().defaultNow(),
  },
);

export const relayTunnels = pgTable(
  "relay_tunnels",
  {
    id: serial("id").primaryKey(),
    sourceNode: text("source_node").notNull(),
    destination: text("destination").notNull(),
    protocol: text("protocol").notNull(),
    status: text("status").notNull().default("pending"),
    createdAt: ts("created_at").notNull().defaultNow(),
  },
);

export const warpPeers = pgTable(
  "warp_peers",
  {
    id: serial("id").primaryKey(),
    peerId: text("peer_id").notNull().unique(),
    publicKey: text("public_key").notNull(),
    endpoint: text("endpoint").notNull(),
    status: text("status").notNull().default("configured"),
    createdAt: ts("created_at").notNull().defaultNow(),
  },
);

export const bpbPolicies = pgTable(
  "bpb_policies",
  {
    id: serial("id").primaryKey(),
    nodeId: integer("node_id").notNull().references(() => nodes.id, { onDelete: "cascade" }),
    bandwidthLimit: integer("bandwidth_limit").notNull(),
    priority: integer("priority").notNull().default(0),
    updatedAt: ts("updated_at").notNull().defaultNow(),
  },
  (t) => [uniqueIndex("bpb_node_uq").on(t.nodeId)],
);
