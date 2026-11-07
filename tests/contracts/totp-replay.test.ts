import test from "node:test";
import assert from "node:assert/strict";
import { eq } from "drizzle-orm";
import { db } from "../../src/db";
import { settings } from "../../src/db/schema";
import { consumeTotpCounter } from "../../src/lib/totp-replay";

test("TOTP step-up consumes each counter once and never accepts equal or older steps", async () => {
  const adminId = 900001;
  const key = `totp.last_counter.${adminId}`;
  await db.delete(settings).where(eq(settings.key, key));
  try {
    await consumeTotpCounter(adminId, 60000001);
    await assert.rejects(() => consumeTotpCounter(adminId, 60000001), /replay refused/i);
    await assert.rejects(() => consumeTotpCounter(adminId, 60000000), /replay refused/i);
    await consumeTotpCounter(adminId, 60000002);
    const [row] = await db.select().from(settings).where(eq(settings.key, key));
    assert.equal(row?.value, "60000002");
  } finally {
    await db.delete(settings).where(eq(settings.key, key));
  }
});

test("concurrent TOTP step-up attempts with the same counter cannot both succeed", async () => {
  const adminId = 900002;
  const key = `totp.last_counter.${adminId}`;
  await db.delete(settings).where(eq(settings.key, key));
  try {
    const outcome = await Promise.allSettled([
      consumeTotpCounter(adminId, 60000001),
      consumeTotpCounter(adminId, 60000001),
    ]);
    assert.equal(outcome.filter((o) => o.status === "fulfilled").length, 1);
    assert.equal(outcome.filter((o) => o.status === "rejected").length, 1);
  } finally {
    await db.delete(settings).where(eq(settings.key, key));
  }
});

test("TOTP counter storage refuses invalid counters without changing state", async () => {
  for (const step of [Number.NaN, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    await assert.rejects(() => consumeTotpCounter(900003, step), /invalid|counter/i);
  }
});
