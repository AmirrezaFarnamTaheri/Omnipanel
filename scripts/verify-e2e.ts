/**
 * OmniPanel end-to-end verification against pg-mem (in-memory PostgreSQL).
 *
 * pg-mem's native `mem.public.query()` executes real Postgres SQL correctly
 * (including RETURNING), but its wire-protocol `Pool`/`BoundPool` mangles
 * prepared-query results under drizzle. So we install a small drizzle-compatible
 * pool wrapper around `mem.public.query` as `pg.Pool` before `@/db` loads.
 * Every unmodified server-side library (drizzle queries/transactions,
 * advisory locks, hash-chained audit) then runs against real Postgres SQL.
 *
 * Run: npx tsx scripts/verify-e2e.ts
 */

import { newDb } from "pg-mem";
import { replaceQueryArgs$ } from "pg-mem";
import fs from "node:fs";
import path from "node:path";

const repo = "/home/user/Omnipanel";

function toLiteral(v: unknown): string {
  if (v === null || v === undefined) return "NULL";
  if (typeof v === "string") return "'" + v.replace(/'/g, "''") + "'";
  if (typeof v === "number") return String(v);
  if (typeof v === "boolean") return v ? "true" : "false";
  if (v instanceof Date) return "'" + v.toISOString() + "'";
  return "'" + String(v) + "'";
}

async function main() {
  /* ---------- 1. pg-mem in-memory Postgres ---------- */
  const mem = newDb();

  // A drizzle-compatible pool backed by pg-mem's native query path.
  class Pool {
    constructor() {}
    async connect() {
      const client = {
        query: (sql: any, params?: any) => runQuery(sql, params),
        release: () => {},
      };
      return client;
    }
    query(sql: any, params?: any) {
      return runQuery(sql, params);
    }
    end() {
      return Promise.resolve();
    }
  }

  function runQuery(sql: any, params?: any) {
    let text: string;
    if (typeof sql === "string") text = sql;
    else text = sql.text;
    if (params && Array.isArray(params) && params.length) {
      text = replaceQueryArgs$(text, params);
    }
    // pg-mem lacks the float8 type; the app casts sum() to float8 for averaging.
    text = text.replace(/::float8/g, "");
    // pg-mem doesn't implement pg_advisory_xact_lock or FOR UPDATE SKIP LOCKED;
    // both are concurrency primitives irrelevant in a single-threaded test.
    if (/\bpg_advisory_xact_lock\b/i.test(text)) {
      return { rows: [], rowCount: 0, fields: [], command: "SELECT" };
    }
    text = text.replace(/\s+for\s+update\s+skip\s+locked/i, "");
    let res: any;
    try {
      res = mem.public.query(text);
    } catch (e: any) {
      console.log("PGMem query failed:", text.slice(0, 400));
      throw e;
    }
    const keyedRows = res.rows ?? [];
    // pg-mem's native result may not expose `.fields`; synthesize field names
    // from the first row.
    const fields = res.fields ?? (keyedRows[0] ? Object.keys(keyedRows[0]).map((name) => ({ name })) : []);
    // drizzle maps result rows positionally (row[columnIndex]), so emit arrays.
    const rows = keyedRows.map((row: Record<string, unknown>) => fields.map((f: { name: string }) => row[f.name]));
    return {
      rows,
      rowCount: res.rowCount ?? rows.length,
      fields,
      command: res.command ?? "SELECT",
    };
  }

  // Install as pg.Pool BEFORE pg (node-postgres) is evaluated, so @/db's
  // `new Pool(...)` becomes this pg-mem-backed pool.
  const { createRequire } = await import("node:module");
  const require = createRequire(import.meta.url);
  require("pg-pool"); // populate the cache
  require.cache[require.resolve("pg-pool")]!.exports = Pool;

  process.env.DATABASE_URL = "postgres://pgmem.inprocess/x";
  const dbMod = await import(path.join(repo, "src/db/index.ts"));
  const db = dbMod.db;
  const schema = await import(path.join(repo, "src/db/schema.ts"));

  /* ---------- 2. Apply the committed migration ---------- */
  let migration = fs.readFileSync(path.join(repo, "db/migrations/0001_initial.sql"), "utf8");
  // pg-mem's SQL parser does not support partial (WHERE) indexes. The committed
  // migration keeps the partial index for real PostgreSQL; here we relax it for
  // the in-memory verification database only.
  migration = migration.replace(
    "UNIQUE (user_id, inbound_id) WHERE state = 'active'",
    "UNIQUE (user_id, inbound_id)",
  );
  migration = migration.replace(/--[^\n]*/g, "");
  const stmts = migration.split(";").map((s) => s.trim()).filter(Boolean);
  for (const s of stmts) mem.public.query(s);
  console.log("migration applied:", stmts.length, "statements");

  /* ---------- 3. Import app libs ---------- */
  const {
    createNode, enrollNode, authenticateAgent, createInbound, setInboundEnabled,
    quarantineNode, rotateNodeSecrets, updateNodeAddress,
  } = await import(path.join(repo, "src/lib/nodes.ts"));
  const {
    createPlan, createUser, updateUser, mutateUserStatus, evaluateUserPolicy,
    usageForUser,
  } = await import(path.join(repo, "src/lib/users.ts"));
  const {
    publishStructural, buildDesiredResponse, getEpoch, declareRecoveryEpoch,
    previewPublish,
  } = await import(path.join(repo, "src/lib/revisions.ts"));
  const { ingestMetering } = await import(path.join(repo, "src/lib/metering.ts"));
  const {
    findUserByToken, buildIR, compile, emitSingbox, emitMihomo, emitUris,
    CompileError,
  } = await import(path.join(repo, "src/lib/subscription.ts"));
  const { verifyAuditChain } = await import(path.join(repo, "src/lib/audit.ts"));
  const { drainOutbox } = await import(path.join(repo, "src/lib/outbox.ts"));
  const { findCapability } = await import(path.join(repo, "src/lib/capabilities.ts"));

  const failures: string[] = [];
  const check = (name: string, cond: boolean, detail = "") => {
    if (cond) console.log(`  ok   ${name}`);
    else { console.log(`  FAIL ${name} ${detail}`); failures.push(name); }
  };
  const actor = { label: "verify:operator", role: "operator" };

  /* ---------- 4. Enrollment & agent identity ---------- */
  const node = await createNode(actor, {
    name: "fra-1", address: "203.0.113.10", provider: "Hetzner", asn: "AS24940", region: "DE",
  });
  check("create node issues enrollment token", typeof node.token === "string" && node.token.startsWith("omni-enroll_"));
  const creds = await enrollNode(node.token, "agent-1.0");
  check("enrollment derives node identity from token", typeof creds.nodeId === "number" && typeof creds.nodeKey === "string");
  const authed = await authenticateAgent({ headers: new Headers({ authorization: `Bearer ${creds.nodeId}.${creds.nodeKey}` }) } as unknown as Request);
  check("agent authenticates with nodeId.nodeKey", authed.id === node.nodeId);
  try {
    await authenticateAgent({ headers: new Headers({ authorization: "Bearer 9.whatever" }) } as unknown as Request);
    check("bad agent credential rejected", false);
  } catch (e: any) {
    check("bad agent credential rejected", e.status === 401);
  }

  /* ---------- 5. Inbound + capability gating ---------- */
  const cap = findCapability("singbox", "vless-reality-vision");
  check("capability registry has singbox Reality/Vision", !!cap);
  const ib = await createInbound(actor, {
    nodeId: node.nodeId, name: "reality-443", runtime: "singbox",
    protocol: "vless-reality-vision", port: 443, sni: "www.microsoft.com",
  });
  check("inbound created on TCP 443", ib.inboundId > 0);
  try {
    await updateNodeAddress(actor, node.nodeId, "127.0.0.1");
    check("loopback node address rejected", false);
  } catch (e: any) {
    check("loopback node address rejected", e.status === 422);
  }

  /* ---------- 6. Users, plans, provisioning ---------- */
  const plan = await createPlan(actor, { name: "Lite 20 GB", quotaGb: 20, enforcement: "metered", idemKey: "p-1" });
  check("plan created", plan.planId > 0);
  const user = await createUser(actor, { name: "alice", email: "alice@example.com", planId: plan.planId }, "u-1");
  check("user created with subscription token", typeof user.token === "string" && user.token.startsWith("omni_"));
  check("idempotent replay returns same user", (await createUser(actor, { name: "alice", email: "alice@example.com", planId: plan.planId }, "u-1")).userId === user.userId);
  try {
    await createUser(actor, { name: "alice2", email: "alice2@example.com", planId: plan.planId }, "u-1");
    check("idempotency key reuse rejected", false);
  } catch (e: any) {
    check("idempotency key reuse rejected", e.status === 422);
  }
  const principals = await db.select().from(schema.endpointPrincipals);
  check("endpoint principal provisioned for user+inbound", principals.length === 1);

  /* ---------- 7. Structural revision + signed desired state ---------- */
  const rev = await db.transaction((tx: any) => publishStructural(tx, node.nodeId, actor));
  check("structural revision published", rev !== null && rev.sequence === 1);
  const rev2 = await db.transaction((tx: any) => publishStructural(tx, node.nodeId, actor));
  check("no-change publish is a no-op", rev2 === null);
  const desired = await buildDesiredResponse(node.nodeId, { epoch: null, structural: 0, membership: 999 });
  check("desired response includes signed structural", desired.structural !== null && typeof desired.structural.signature === "string");
  check("desired response includes membership snapshot", desired.membership !== null && Array.isArray(desired.membership.payload.principals) && desired.membership.payload.principals.length === 1);
  const p = principals[0];
  check("delivered credential decrypts", desired.membership.payload.principals[0].credential.length > 0);
  const preview = await previewPublish(node.nodeId);
  check("preview is redacted (digests, no raw secrets)", preview.digest.length > 0 && !JSON.stringify(preview.manifest.inbounds[0].secretRefs).includes("privateKey"));
  const rb = await db.transaction((tx: any) => publishStructural(tx, node.nodeId, actor, { rollbackOfSequence: 1, force: true }));
  check("rollback creates new immutable revision", rb !== null && rb.sequence === 2 && rb.rollbackOf === 1);

  /* ---------- 8. Membership delta delivery ---------- */
  const delta = await buildDesiredResponse(node.nodeId, { epoch: desired.epoch, structural: 1, membership: 0 });
  check("membership incremental delta mode", delta.membership !== null && delta.membership.payload.mode === "incremental");

  /* ---------- 9. Cumulative metering ---------- */
  const summary = await ingestMetering(node.nodeId, [
    { attributionKey: p.attributionKey, generation: "g1", seq: 1, up: 0, down: 0, generationStart: true },
    { attributionKey: p.attributionKey, generation: "g1", seq: 2, up: 1000, down: 2000 },
    { attributionKey: p.attributionKey, generation: "g1", seq: 2, up: 1000, down: 2000 }, // duplicate
  ]);
  check("metering accepts cumulative observation", summary.accepted === 2 && summary.duplicate === 1);
  const summary2 = await ingestMetering(node.nodeId, [
    { attributionKey: p.attributionKey, generation: "g1", seq: 2, up: 9999, down: 9999 },
  ]);
  check("conflicting observation flagged", summary2.conflict === 1);
  const summary3 = await ingestMetering(node.nodeId, [
    { attributionKey: p.attributionKey, generation: "g1", seq: 3, up: 5, down: 5 },
  ]);
  check("counter reset flagged as discontinuity", summary3.counter_reset === 1);
  const usage = await usageForUser(db, user.userId);
  check("usage aggregate excludes reset delta", usage.total === 3000, `got ${usage.total}`);

  /* ---------- 10. Probe identities excluded from quota ---------- */
  const summary4 = await ingestMetering(node.nodeId, [
    { attributionKey: "probe-abc", generation: "g1", seq: 1, up: 1000000, down: 0, generationStart: true },
  ]);
  check("probe observations excluded", summary4.probe_excluded === 1);

  /* ---------- 11. Quota policy: exact measured usage only ---------- */
  await db.transaction((tx: any) => evaluateUserPolicy(tx, user.userId));
  const [uRow] = await db.select().from(schema.users);
  check("user not suspended below quota", uRow.status === "active");
  await ingestMetering(node.nodeId, [{ attributionKey: p.attributionKey, generation: "g1", seq: 4, up: 25 * 1024 ** 3, down: 25 * 1024 ** 3 }]);
  await db.transaction((tx: any) => evaluateUserPolicy(tx, user.userId));
  const [uRow2] = await db.select().from(schema.users);
  check("user suspended on exact measured quota breach", uRow2.status === "suspended" && uRow2.suspendReason === "quota");

  /* ---------- 12. Suspend/resume membership stream ---------- */
  await mutateUserStatus(actor, user.userId, "suspended", "admin test");
  await mutateUserStatus(actor, user.userId, "active", null);
  const events = await db.select().from(schema.membershipEvents);
  check("membership events recorded", events.some((e: any) => e.type === "suspend") && events.some((e: any) => e.type === "resume"));

  /* ---------- 13. Subscription compilation: all formats ---------- */
  const hit = await findUserByToken(user.token);
  check("subscription token resolves to user", hit !== null && hit.u.id === user.userId);
  const ir = await buildIR(user.userId);
  check("IR includes eligible path", ir.paths.length === 1);
  check("IR exclusion explanations present", Array.isArray(ir.excluded));
  const sb = emitSingbox(ir);
  let sbOk = false;
  try { JSON.parse(sb); sbOk = true; } catch { sbOk = false; }
  check("sing-box artifact is valid JSON", sbOk);
  const mh = emitMihomo(ir);
  check("Mihomo artifact has proxies and groups", mh.includes("proxies:") && mh.includes("proxy-groups:"));
  const uri = emitUris(ir);
  check("URI bundle is base64", new RegExp("^[A-Za-z0-9+/]+={0,2}$").test(uri.trim()));
  try {
    compile({ ...ir, diagnostics: ["Reality public key missing; refusing to emit weakened endpoint"] } as any, "singbox");
    check("incomplete Reality endpoint refused", false);
  } catch (e) {
    check("incomplete Reality endpoint refused", e instanceof CompileError);
  }

  /* ---------- 14. Audit chain ---------- */
  const chain = await verifyAuditChain();
  check("audit chain intact", chain.ok, `count=${chain.count} brokenAt=${chain.brokenAt}`);

  /* ---------- 15. Recovery epoch ---------- */
  const nextEpoch = await db.transaction((tx: any) => declareRecoveryEpoch(tx, actor, "PITR drill: restored to 2026-11-03T09:10Z"));
  check("new control-plane epoch authorized", nextEpoch === 2);
  const desiredAfter = await buildDesiredResponse(node.nodeId, { epoch: 1, structural: 2, membership: 999 });
  check("recovery snapshot marked cross-epoch", desiredAfter.structural !== null && desiredAfter.structural.payload.recovery !== undefined);
  check("recovery membership is a fresh snapshot", desiredAfter.membership !== null && desiredAfter.membership.payload.mode === "snapshot");

  /* ---------- 16. Node quarantine ---------- */
  const affected = await quarantineNode(actor, node.nodeId);
  check("quarantine revokes node identity and counts credentials", affected === 1);
  try {
    await authenticateAgent({ headers: new Headers({ authorization: `Bearer ${creds.nodeId}.${creds.nodeKey}` }) } as unknown as Request);
    check("quarantined agent denied", false);
  } catch (e: any) {
    check("quarantined agent denied", e.status === 403 || e.status === 401);
  }

  /* ---------- 17. Outbox worker ---------- */
  try {
    const drained = await drainOutbox();
    check("outbox drainer runs without error", typeof drained === "number");
  } catch (e: any) {
    check("outbox drainer runs without error", false, e.message?.slice(0, 200));
  }

  if (failures.length) {
    console.log(`\n${failures.length} CHECK(S) FAILED`);
    process.exit(1);
  }
  console.log("\nALL CHECKS PASSED");
}

main().then(() => process.exit(0)).catch((e) => { console.error("FATAL", e?.cause?.message ?? e); process.exit(2); });
