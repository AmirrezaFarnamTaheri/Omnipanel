import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import { DataType, newDb } from "pg-mem";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

function getLocalKek(): Buffer {
  const fromEnv = process.env.OMNI_KEK;
  if (fromEnv) {
    const buf = Buffer.from(fromEnv, "base64");
    if (buf.length === 32) return buf;
  }
  const dir = path.join(process.cwd(), ".data");
  const file = path.join(dir, "kek");
  if (fs.existsSync(file)) {
    return Buffer.from(fs.readFileSync(file, "utf8").trim(), "base64");
  }
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const k = crypto.randomBytes(32);
  fs.writeFileSync(file, k.toString("base64"), { mode: 0o600 });
  return k;
}

function encryptSecret(plain: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", getLocalKek(), iv);
  const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  return ["v1", iv.toString("base64"), cipher.getAuthTag().toString("base64"), ct.toString("base64")].join(".");
}

const sha256 = (s: string) => crypto.createHash("sha256").update(s).digest("hex");
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString("base64url");

function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16);
  const dk = crypto.scryptSync(password, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
  return `scrypt$${salt.toString("base64")}$${dk.toString("base64")}`;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`)
    .join(",")}}`;
}

function newRealityKeypair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("x25519");
  const priv = privateKey.export({ format: "jwk" }) as { d: string };
  const pub = publicKey.export({ format: "jwk" }) as { x: string };
  return { privateKey: priv.d, publicKey: pub.x, shortId: crypto.randomBytes(8).toString("hex") };
}

const databaseUrl = process.env.DATABASE_URL;

const globalForDb = globalThis as typeof globalThis & {
  __arenaNextJsPostgresqlPool?: Pool;
  __omniEmbeddedSeeded?: boolean;
};

function createEmbeddedPool(): Pool {
  const mem = newDb({ autoCreateForeignKeyIndices: true });

  mem.public.registerFunction({
    name: "pg_advisory_xact_lock",
    args: [DataType.integer],
    returns: DataType.integer,
    implementation: () => 1,
  });

  mem.public.registerFunction({
    name: "clock_timestamp",
    args: [],
    returns: DataType.timestamptz,
    implementation: () => new Date(),
  });

  mem.public.registerFunction({
    name: "current_database",
    args: [],
    returns: DataType.text,
    implementation: () => "omnipanel_embedded",
  });

  mem.public.none(`
    CREATE TABLE settings (
      key text PRIMARY KEY,
      value text NOT NULL
    );

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
  `);

  // Seed deterministic initial state synchronously before returning pool
  seedEmbeddedDatabaseSync(mem);

  const { Pool: MemPool } = mem.adapters.createPg();
  const poolInstance = new MemPool() as any;

  const splitTopLevelCommas = (segment: string): string[] => {
    const parts: string[] = [];
    let depth = 0;
    let inSingle = false;
    let inDouble = false;
    let start = 0;
    for (let i = 0; i < segment.length; i++) {
      const ch = segment[i];
      if (ch === "'" && !inDouble) {
        if (inSingle && segment[i + 1] === "'") {
          i++;
          continue;
        }
        inSingle = !inSingle;
      } else if (ch === '"' && !inSingle) {
        inDouble = !inDouble;
      } else if (!inSingle && !inDouble) {
        if (ch === "(") depth++;
        else if (ch === ")") depth = Math.max(0, depth - 1);
        else if (ch === "," && depth === 0) {
          parts.push(segment.slice(start, i).trim());
          start = i + 1;
        }
      }
    }
    parts.push(segment.slice(start).trim());
    return parts;
  };

  const findTopLevelKeyword = (sqlText: string, keyword: string, startIndex = 0): number => {
    const lower = sqlText.toLowerCase();
    let depth = 0;
    let inSingle = false;
    let inDouble = false;
    for (let i = startIndex; i <= sqlText.length - keyword.length; i++) {
      const ch = sqlText[i];
      if (ch === "'" && !inDouble) {
        if (inSingle && sqlText[i + 1] === "'") {
          i++;
          continue;
        }
        inSingle = !inSingle;
      } else if (ch === '"' && !inSingle) {
        inDouble = !inDouble;
      } else if (!inSingle && !inDouble) {
        if (ch === "(") depth++;
        else if (ch === ")") depth = Math.max(0, depth - 1);
        else if (depth === 0 && lower.startsWith(keyword, i)) {
          return i;
        }
      }
    }
    return -1;
  };

  const aliasForRowMode = (rawSql: string): { text: string; keys: string[] } | null => {
    const sqlText = rawSql.replace(/::float8\b/gi, "::float");
    const trimmed = sqlText.trim();
    const lower = trimmed.toLowerCase();

    if (lower.startsWith("select ")) {
      const fromIdx = findTopLevelKeyword(trimmed, " from ", 7);
      if (fromIdx > 7) {
        const selectList = trimmed.slice(7, fromIdx);
        const cols = splitTopLevelCommas(selectList);
        if (cols.length > 0 && !cols.some((c) => c === "*")) {
          const keys = cols.map((_, idx) => `__c${idx}`);
          const aliased = cols
            .map((c, idx) => `${c.replace(/\s+as\s+"?[a-zA-Z0-9_]+"?$/i, "")} as "${keys[idx]}"`)
            .join(", ");
          return {
            text: `select ${aliased}${trimmed.slice(fromIdx)}`,
            keys,
          };
        }
      }
    }

    const retIdx = findTopLevelKeyword(trimmed, " returning ", 0);
    if (retIdx > 0) {
      const retList = trimmed.slice(retIdx + 11);
      const cols = splitTopLevelCommas(retList);
      if (cols.length > 0 && !cols.some((c) => c === "*")) {
        const keys = cols.map((_, idx) => `__c${idx}`);
        const aliased = cols
          .map((c, idx) => `${c.replace(/\s+as\s+"?[a-zA-Z0-9_]+"?$/i, "")} as "${keys[idx]}"`)
          .join(", ");
        return {
          text: `${trimmed.slice(0, retIdx)} returning ${aliased}`,
          keys,
        };
      }
    }

    return null;
  };

  const patchQuery = (target: any) => {
    const origQuery = target.query.bind(target);
    target.query = async (queryTextOrConfig: any, values?: any, callback?: any) => {
      if (queryTextOrConfig && typeof queryTextOrConfig === "object") {
        const isArrayMode = queryTextOrConfig.rowMode === "array";
        const { rowMode: _rm, types: _tp, ...restConfig } = queryTextOrConfig;
        let customKeys: string[] | null = null;
        if (typeof restConfig.text === "string") {
          restConfig.text = restConfig.text.replace(/::float8\b/gi, "::float");
          if (isArrayMode) {
            const rewritten = aliasForRowMode(restConfig.text);
            if (rewritten) {
              restConfig.text = rewritten.text;
              customKeys = rewritten.keys;
            }
          }
        }
        const res = await origQuery(restConfig, values);
        if (isArrayMode) {
          const fieldNames: string[] | null =
            customKeys ??
            (Array.isArray(res?.fields) && res.fields.length > 0
              ? res.fields.map((f: any) => f.name)
              : null);
          const arrayRows = (res?.rows ?? []).map((row: Record<string, unknown>) =>
            fieldNames ? fieldNames.map((k) => row[k]) : Object.values(row),
          );
          const patched = { ...res, rows: arrayRows };
          if (typeof callback === "function") {
            callback(null, patched);
            return;
          }
          return patched;
        }
        if (typeof callback === "function") {
          callback(null, res);
          return;
        }
        return res;
      }
      if (typeof queryTextOrConfig === "string") {
        return origQuery(queryTextOrConfig.replace(/::float8\b/gi, "::float"), values, callback);
      }
      return origQuery(queryTextOrConfig, values, callback);
    };
  };

  patchQuery(poolInstance);
  const origConnect = poolInstance.connect.bind(poolInstance);
  poolInstance.connect = async (...args: any[]) => {
    const client = await origConnect(...args);
    if (client && !client.__omniRowModePatched) {
      patchQuery(client);
      client.__omniRowModePatched = true;
    }
    return client;
  };

  return poolInstance as Pool;
}

function sqlStr(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function seedEmbeddedDatabaseSync(mem: ReturnType<typeof newDb>) {
  if (globalForDb.__omniEmbeddedSeeded) return;
  globalForDb.__omniEmbeddedSeeded = true;

  const now = new Date();
  const periodBucket = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1, 12, 0, 0));
  const recentSeen = new Date(now.getTime() - 25_000);
  const nextMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 15));
  const futureExpiry = new Date(now.getTime() + 6 * 3600_000);

  let prevHash = "genesis";
  const auditEntries: Array<{
    ts: Date;
    actor: string;
    action: string;
    objectType: string;
    objectId: string;
    detail: Record<string, unknown>;
    prevHash: string;
    hash: string;
  }> = [];

  const appendAudit = (
    actor: string,
    action: string,
    objectType: string,
    objectId: string | number,
    detail: Record<string, unknown>,
    offsetSec: number,
  ) => {
    const ts = new Date(now.getTime() - offsetSec * 1000);
    const hash = sha256(
      prevHash +
        canonicalJson({
          ts: ts.toISOString(),
          actor,
          action,
          objectType,
          objectId: String(objectId),
          detail,
        }),
    );
    auditEntries.push({ ts, actor, action, objectType, objectId: String(objectId), detail, prevHash, hash });
    prevHash = hash;
  };

  const ownerPw = hashPassword("OmniPanel#Owner2026!");
  const reviewerPw = hashPassword("OmniPanel#Review2026!");
  const operatorPw = hashPassword("OmniPanel#Ops2026!");

  const rk1 = newRealityKeypair();
  const rk2 = newRealityKeypair();
  const u1Cred1 = encryptSecret(crypto.randomUUID());
  const u1Cred2 = encryptSecret(crypto.randomUUID());
  const u2Cred1 = encryptSecret(crypto.randomUUID());
  const u2Cred2 = encryptSecret(crypto.randomUUID());

  const subTok1 = `omni_${randomToken(32)}`;
  const subTok2 = `omni_${randomToken(32)}`;

  const manifest1 = {
    schema: "omni.desired-state/v1",
    node: { id: 1, name: "fra-edge-1" },
    egress: { mode: "direct", denyCidrs: ["127.0.0.0/8", "::1/128", "169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] },
    inbounds: [
      {
        id: 1,
        name: "reality-tcp-443",
        protocol: "vless-reality-vision",
        runtime: "singbox",
        transport: "tcp",
        port: 443,
        sni: "www.cloudflare.com",
        params: { realityPublicKey: rk1.publicKey, shortId: rk1.shortId, flow: "xtls-rprx-vision", fingerprint: "chrome" },
        secretRefs: { realityPrivateKey: { ref: "inbound/1/realityPrivateKey", digest: sha256(rk1.privateKey) } },
      },
    ],
  };
  const digest1 = sha256(canonicalJson(manifest1));

  const manifest2 = {
    schema: "omni.desired-state/v1",
    node: { id: 2, name: "ams-edge-2" },
    egress: { mode: "direct", denyCidrs: ["127.0.0.0/8", "::1/128", "169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] },
    inbounds: [
      {
        id: 2,
        name: "reality-tcp-8443",
        protocol: "vless-reality-vision",
        runtime: "singbox",
        transport: "tcp",
        port: 8443,
        sni: "dl.google.com",
        params: { realityPublicKey: rk2.publicKey, shortId: rk2.shortId, flow: "xtls-rprx-vision", fingerprint: "chrome" },
        secretRefs: { realityPrivateKey: { ref: "inbound/2/realityPrivateKey", digest: sha256(rk2.privateKey) } },
      },
    ],
  };
  const digest2 = sha256(canonicalJson(manifest2));

  const initialResources = {
    "1": {
      nodeId: "fra-edge-1",
      generation: 4,
      sampledAt: recentSeen.toISOString(),
      cpuPercent: 18.4,
      memoryTotalBytes: 8_589_934_592,
      memoryUsedBytes: 1_942_000_000,
      filesystems: [
        { id: "/", totalBytes: 85_899_345_920, usedBytes: 14_200_000_000 },
        { id: "/var/lib/sing-box", totalBytes: 21_474_836_480, usedBytes: 2_140_000_000 },
      ],
      network: [
        { interface: "eth0", receivedBytes: 84_210_450_112, sentBytes: 129_804_112_896 },
      ],
    },
    "2": {
      nodeId: "ams-edge-2",
      generation: 3,
      sampledAt: recentSeen.toISOString(),
      cpuPercent: 11.2,
      memoryTotalBytes: 4_294_967_296,
      memoryUsedBytes: 1_410_000_000,
      filesystems: [
        { id: "/", totalBytes: 53_687_091_200, usedBytes: 9_800_000_000 },
      ],
      network: [
        { interface: "eth0", receivedBytes: 41_900_220_416, sentBytes: 63_120_880_640 },
      ],
    },
  };

  const initialBackupTasks = [
    {
      id: "backup-genesis-01",
      kind: "backup",
      state: "succeeded",
      attempt: 1,
      storageTarget: "local:/var/lib/omnipanel/archives/snap-epoch1.tar.zst",
      artifactDigest: `sha256:${sha256("omni-archive:backup-genesis-01")}`,
      errorCode: "",
      createdAt: new Date(now.getTime() - 1800_000).toISOString(),
      updatedAt: new Date(now.getTime() - 1740_000).toISOString(),
    },
    {
      id: "backup-daily-02",
      kind: "backup",
      state: "running",
      attempt: 1,
      storageTarget: "s3://omni-dr-vault-eu/control-plane/epoch-1-daily.tar.zst",
      artifactDigest: "",
      errorCode: "",
      createdAt: new Date(now.getTime() - 300_000).toISOString(),
      updatedAt: new Date(now.getTime() - 240_000).toISOString(),
    },
  ];

  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const signingKeypair = {
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };

  const proposalExp = new Date(now.getTime() + 540_000);
  const envManifest2 = {
    schema: "omni.desired-state/v1" as const,
    nodeId: "node-1-fra-edge-1",
    controlPlaneEpoch: "epoch-1",
    structuralSequence: 2,
    membershipSequence: 2,
    issuedAt: recentSeen.toISOString(),
    expiresAt: proposalExp.toISOString(),
    disruption: "listener_restart",
    payload: manifest1,
  };
  const canonicalManifest2 = canonicalJson(envManifest2);
  const sig2 = crypto.sign(null, Buffer.from(canonicalManifest2, "utf8"), privateKey).toString("base64");
  const envelope2 = {
    version: "ed25519-jcs-v1" as const,
    keyId: "cp-ed25519-k1",
    manifestDigest: `sha256:${sha256(canonicalManifest2)}`,
    signature: sig2,
    manifest: envManifest2,
  };
  const envelopeJson2 = canonicalJson(envelope2);
  const envelopeSha256_2 = sha256(envelopeJson2);

  const envManifest1 = {
    schema: "omni.desired-state/v1" as const,
    nodeId: "node-1-fra-edge-1",
    controlPlaneEpoch: "epoch-1",
    structuralSequence: 1,
    membershipSequence: 2,
    issuedAt: new Date(now.getTime() - 1500_000).toISOString(),
    expiresAt: proposalExp.toISOString(),
    disruption: "listener_restart",
    payload: manifest1,
  };
  const canonicalManifest1 = canonicalJson(envManifest1);
  const sig1 = crypto.sign(null, Buffer.from(canonicalManifest1, "utf8"), privateKey).toString("base64");
  const envelope1 = {
    version: "ed25519-jcs-v1" as const,
    keyId: "cp-ed25519-k1",
    manifestDigest: `sha256:${sha256(canonicalManifest1)}`,
    signature: sig1,
    manifest: envManifest1,
  };
  const envelopeJson1 = canonicalJson(envelope1);
  const envelopeSha256_1 = sha256(envelopeJson1);

  const initialProposals = [
    {
      proposalId: "prop-n1-s2-pending",
      nodeId: 1,
      nodeName: "fra-edge-1",
      nodeUuid: "node-1-fra-edge-1",
      controlPlaneEpoch: 1,
      structuralSequence: 2,
      membershipSequence: 2,
      disruption: "listener_restart",
      envelopeJson: envelopeJson2,
      envelopeSha256: envelopeSha256_2,
      proposerAdminId: 1,
      proposerEmail: "owner@omnipanel.internal",
      createdAt: recentSeen.toISOString(),
      expiresAt: proposalExp.toISOString(),
      note: "Scheduled Reality shortId rotation & nftables egress guard verification on fra-edge-1",
    },
    {
      proposalId: "prop-n1-s1-published",
      nodeId: 1,
      nodeName: "fra-edge-1",
      nodeUuid: "node-1-fra-edge-1",
      controlPlaneEpoch: 1,
      structuralSequence: 1,
      membershipSequence: 2,
      disruption: "listener_restart",
      envelopeJson: envelopeJson1,
      envelopeSha256: envelopeSha256_1,
      proposerAdminId: 1,
      proposerEmail: "owner@omnipanel.internal",
      createdAt: new Date(now.getTime() - 1500_000).toISOString(),
      expiresAt: proposalExp.toISOString(),
      note: "Initial Reality/Vision listener baseline publication",
      decision: {
        approvalId: "appr-n1-s1-baseline",
        approverAdminId: 2,
        approverEmail: "reviewer@omnipanel.internal",
        reviewedSha256: envelopeSha256_1,
        approvedAt: new Date(now.getTime() - 1300_000).toISOString(),
        approvalExpiresAt: proposalExp.toISOString(),
        consumedAt: new Date(now.getTime() - 1200_000).toISOString(),
        publishedRevisionSeq: 1,
      },
    },
  ];

  appendAudit("admin:owner@omnipanel.internal", "admin.bootstrap", "admin", 1, { role: "owner" }, 3600);
  appendAudit("admin:owner@omnipanel.internal", "node.create", "node", 1, { name: "fra-edge-1", provider: "Hetzner", asn: "AS24940" }, 3200);
  appendAudit("admin:owner@omnipanel.internal", "node.create", "node", 2, { name: "ams-edge-2", provider: "DigitalOcean", asn: "AS14061" }, 3000);
  appendAudit("admin:owner@omnipanel.internal", "plan.create", "plan", 1, { name: "Standard Metered 100 GB", quotaBytes: 100 * 1024 ** 3, enforcement: "metered" }, 2600);
  appendAudit("admin:owner@omnipanel.internal", "plan.create", "plan", 2, { name: "Research Unmetered", quotaBytes: null, enforcement: "unmetered" }, 2500);
  appendAudit("admin:owner@omnipanel.internal", "user.create", "user", 1, { name: "Elena Rostova", planId: 1, endpoints: 2 }, 2000);
  appendAudit("admin:owner@omnipanel.internal", "user.create", "user", 2, { name: "Marcus Vance", planId: 2, endpoints: 2 }, 1800);
  appendAudit("admin:reviewer@omnipanel.internal", "desired_proposal.approve", "desired_proposal", "prop-n1-s1-published", { nodeId: 1, structuralSequence: 1, envelopeSha256: envelopeSha256_1 }, 1300);
  appendAudit("admin:owner@omnipanel.internal", "revision.publish", "node", 1, { sequence: 1, epoch: 1, digest: digest1, disruption: "listener_restart" }, 1200);
  appendAudit("admin:owner@omnipanel.internal", "revision.publish", "node", 2, { sequence: 1, epoch: 1, digest: digest2, disruption: "listener_restart" }, 1100);
  appendAudit("admin:owner@omnipanel.internal", "capability.evidence", "capability", "singbox:vless-reality-vision", { claim: "admission", status: "verified", note: "Run 41809579179 isolated Linux netns Reality/Vision L3 smoke passed (1.14.4+omni.2)" }, 600);

  const componentsJson = sqlStr(
    JSON.stringify([
      { name: "sing-box@1.14.4+omni.2", state: "running" },
      { name: "nftables-egress-guard", state: "enforced" },
      { name: "sqlite-wal-journal", state: "synced" },
    ]),
  );

  mem.public.none(`
    INSERT INTO settings (key, value) VALUES
      ('control_plane_epoch', '1'),
      ('sub.profile_title_prefix', 'OmniPanel'),
      ('sub.support_url', 'https://status.omnipanel.internal/support'),
      ('sub.web_page_url', 'https://portal.omnipanel.internal/account'),
      ('sub.announce', 'Sing-box v1.14.4+omni.2 namespace smoke verified; external M0 lab gate remains active.'),
      ('sub.expiry_presentation', 'exclusive'),
      ('sub.update_interval_hours', '12'),
      ('node.resources', ${sqlStr(JSON.stringify(initialResources))}),
      ('backup.tasks', ${sqlStr(JSON.stringify(initialBackupTasks))}),
      ('desired.signing_keypair', ${sqlStr(JSON.stringify(signingKeypair))}),
      ('desired.proposals', ${sqlStr(JSON.stringify(initialProposals))})
    ON CONFLICT DO NOTHING;

    INSERT INTO admins (email, password_hash, role, totp_enabled) VALUES
      ('owner@omnipanel.internal', ${sqlStr(ownerPw)}, 'owner', true),
      ('reviewer@omnipanel.internal', ${sqlStr(reviewerPw)}, 'owner', true),
      ('ops@omnipanel.internal', ${sqlStr(operatorPw)}, 'operator', false);

    INSERT INTO nodes (
      name, public_address, provider, asn, region, status, last_seen_at, agent_version,
      structural_seq, membership_seq, applied_epoch, applied_structural_seq, applied_membership_seq, applied_state, components
    ) VALUES
      ('fra-edge-1', '198.51.100.10', 'Hetzner', 'AS24940', 'Falkenstein, DE', 'active', ${sqlStr(recentSeen.toISOString())}, 'omni-node/0.2.0-lab', 1, 2, 1, 1, 2, 'VERIFIED', ${componentsJson}),
      ('ams-edge-2', '203.0.113.25', 'DigitalOcean', 'AS14061', 'Amsterdam, NL', 'active', ${sqlStr(recentSeen.toISOString())}, 'omni-node/0.2.0-lab', 1, 2, 1, 1, 2, 'VERIFIED', ${componentsJson});

    INSERT INTO inbounds (node_id, name, runtime, protocol, transport, port, sni, params, secrets, enabled) VALUES
      (1, 'reality-tcp-443', 'singbox', 'vless-reality-vision', 'tcp', 443, 'www.cloudflare.com',
       ${sqlStr(JSON.stringify({ realityPublicKey: rk1.publicKey, shortId: rk1.shortId, flow: "xtls-rprx-vision", fingerprint: "chrome" }))},
       ${sqlStr(JSON.stringify({ realityPrivateKey: encryptSecret(rk1.privateKey) }))}, true),
      (2, 'reality-tcp-8443', 'singbox', 'vless-reality-vision', 'tcp', 8443, 'dl.google.com',
       ${sqlStr(JSON.stringify({ realityPublicKey: rk2.publicKey, shortId: rk2.shortId, flow: "xtls-rprx-vision", fingerprint: "chrome" }))},
       ${sqlStr(JSON.stringify({ realityPrivateKey: encryptSecret(rk2.privateKey) }))}, true);

    INSERT INTO inbound_health (inbound_id, state, since, updated_at) VALUES
      (1, 'healthy', ${sqlStr(recentSeen.toISOString())}, ${sqlStr(recentSeen.toISOString())}),
      (2, 'healthy', ${sqlStr(recentSeen.toISOString())}, ${sqlStr(recentSeen.toISOString())});

    INSERT INTO health_observations (node_id, inbound_id, vantage, level, ok, latency_ms, detail, observed_at) VALUES
      (1, 1, 'eu-central-probe', 'L3', true, 14, 'reality handshake + echo verified', ${sqlStr(recentSeen.toISOString())}),
      (1, 1, 'us-east-probe', 'L2', true, 88, 'authenticated session ok', ${sqlStr(recentSeen.toISOString())}),
      (2, 2, 'eu-west-probe', 'L3', true, 11, 'reality handshake + echo verified', ${sqlStr(recentSeen.toISOString())});

    INSERT INTO plans (name, quota_bytes, enforcement) VALUES
      ('Standard Metered 100 GB', ${100 * 1024 ** 3}, 'metered'),
      ('Research Unmetered', NULL, 'unmetered');

    INSERT INTO users (name, email, plan_id, status, expires_at, version) VALUES
      ('Elena Rostova', 'elena.rostova@omnipanel.internal', 1, 'active', ${sqlStr(nextMonth.toISOString())}, 1),
      ('Marcus Vance', 'marcus.vance@omnipanel.internal', 2, 'active', ${sqlStr(nextMonth.toISOString())}, 1);

    INSERT INTO subscription_tokens (user_id, token_hash, prefix, last_used_at) VALUES
      (1, ${sqlStr(sha256(subTok1))}, ${sqlStr(subTok1.slice(0, 9))}, ${sqlStr(recentSeen.toISOString())}),
      (2, ${sqlStr(sha256(subTok2))}, ${sqlStr(subTok2.slice(0, 9))}, ${sqlStr(recentSeen.toISOString())});

    INSERT INTO endpoint_principals (user_id, inbound_id, attribution_key, credential_enc, state) VALUES
      (1, 1, 'u1-i1-a1b2c3', ${sqlStr(u1Cred1)}, 'active'),
      (1, 2, 'u1-i2-d4e5f6', ${sqlStr(u1Cred2)}, 'active'),
      (2, 1, 'u2-i1-778899', ${sqlStr(u2Cred1)}, 'active'),
      (2, 2, 'u2-i2-aabbcc', ${sqlStr(u2Cred2)}, 'active');

    INSERT INTO structural_revisions (node_id, epoch, sequence, digest, manifest, disruption, created_by, created_at) VALUES
      (1, 1, 1, ${sqlStr(digest1)}, ${sqlStr(JSON.stringify(manifest1))}, 'listener_restart', 'admin:owner@omnipanel.internal', ${sqlStr(recentSeen.toISOString())}),
      (2, 1, 1, ${sqlStr(digest2)}, ${sqlStr(JSON.stringify(manifest2))}, 'listener_restart', 'admin:owner@omnipanel.internal', ${sqlStr(recentSeen.toISOString())});

    INSERT INTO deployment_attempts (node_id, epoch, structural_seq, state, components, reported_at) VALUES
      (1, 1, 1, 'VERIFIED', ${componentsJson}, ${sqlStr(recentSeen.toISOString())}),
      (2, 1, 1, 'VERIFIED', ${componentsJson}, ${sqlStr(recentSeen.toISOString())});

    INSERT INTO usage_aggregates (user_id, bucket, up, down) VALUES
      (1, ${sqlStr(periodBucket.toISOString())}, ${Math.round(4.2 * 1024 ** 3)}, ${Math.round(18.6 * 1024 ** 3)}),
      (2, ${sqlStr(periodBucket.toISOString())}, ${Math.round(1.1 * 1024 ** 3)}, ${Math.round(6.4 * 1024 ** 3)});

    INSERT INTO capability_evidence (capability_key, claim, status, note, recorded_by, recorded_at) VALUES
      ('singbox:vless-reality-vision', 'admission', 'verified', 'Run 41809579179: isolated netns Reality/Vision L3 smoke passed (1.14.4+omni.2)', 'owner@omnipanel.internal', ${sqlStr(recentSeen.toISOString())}),
      ('singbox:vless-reality-vision', 'metering', 'verified', 'Run 41809579179: 1,048,576 B bidirectional payload 0.0% counter delta error', 'owner@omnipanel.internal', ${sqlStr(recentSeen.toISOString())});
  `);

  for (const a of auditEntries) {
    mem.public.none(`
      INSERT INTO audit_log (ts, actor, action, object_type, object_id, detail, prev_hash, hash)
      VALUES (
        ${sqlStr(a.ts.toISOString())},
        ${sqlStr(a.actor)},
        ${sqlStr(a.action)},
        ${sqlStr(a.objectType)},
        ${sqlStr(a.objectId)},
        ${sqlStr(JSON.stringify(a.detail))},
        ${sqlStr(a.prevHash)},
        ${sqlStr(a.hash)}
      );
    `);
  }
}

const useEmbedded =
  !databaseUrl ||
  databaseUrl.startsWith("pg-mem://") ||
  databaseUrl === "postgres://test:test@127.0.0.1:5432/omnipanel_test";

export const pool: Pool =
  globalForDb.__arenaNextJsPostgresqlPool ??
  (useEmbedded
    ? createEmbeddedPool()
    : new Pool({
        connectionString: databaseUrl,
      }));

if (process.env.NODE_ENV !== "production") {
  globalForDb.__arenaNextJsPostgresqlPool = pool;
}

export const db = drizzle(pool);

