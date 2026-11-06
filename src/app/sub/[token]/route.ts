import { db } from "@/db";
import { subscriptionTokens } from "@/db/schema";
import { eq } from "drizzle-orm";
import { clientForRequest } from "@/lib/capabilities";
import { problemResponse, ProblemError } from "@/lib/problem";
import { rateLimit } from "@/lib/ratelimit";
import { buildIR, compile, CompileError, findUserByToken } from "@/lib/subscription";
import { profileMetadataHeaders, subscriptionUserinfo } from "@/lib/subscription-profile";
import { getSubscriptionProfileConfig } from "@/lib/governance-store";
import { computeSubscriptionEtag, matchesIfNoneMatch } from "@/lib/enterprise-hardening";
import { usageForUser } from "@/lib/users";

export const dynamic = "force-dynamic";

const HEADERS = { "cache-control": "private, no-cache", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer" };

export async function GET(req: Request, ctx: { params: Promise<{ token: string }> }) {
  try {
    // Public subscription traffic has its own budget, isolated from agent reconciliation buckets.
    if (!rateLimit("sub:global", 200, 50)) throw new ProblemError(429, "Too many requests", "Try again shortly");
    const { token } = await ctx.params;
    const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
    if (!/^omni_[A-Za-z0-9_-]{43}$/.test(token)) {
      if (!rateLimit(`sub:bad:${ip}`, 10, 0.2)) throw new ProblemError(429, "Too many requests", "Try again shortly");
      throw new ProblemError(404, "Not found", "Subscription not found");
    }
    const hit = await findUserByToken(token);
    if (!hit) {
      if (!rateLimit(`sub:bad:${ip}`, 10, 0.2)) throw new ProblemError(429, "Too many requests", "Try again shortly");
      throw new ProblemError(404, "Not found", "Subscription not found");
    }
    const { u, t } = hit;
    const url = new URL(req.url);
    const format = clientForRequest(url.searchParams.get("format"), req.headers.get("user-agent"));
    const usage = await usageForUser(db, u.id);
    const ir = await buildIR(u.id, format);
    const profileCfg = await getSubscriptionProfileConfig();
    const userinfo = subscriptionUserinfo({
      uploadBytes: usage.up,
      downloadBytes: usage.down,
      quotaBytes: ir.quotaBytes,
      expiresAt: u.expiresAt,
      expiryPresentation: profileCfg.expiryPresentation,
    });
    if (u.status !== "active") {
      // No usable credentials are ever returned for suspended or expired users.
      return new Response(`Subscription ${u.status}${u.suspendReason ? ` (${u.suspendReason})` : ""}`, {
        status: 403,
        headers: { ...HEADERS, "content-type": "text/plain; charset=utf-8", "subscription-userinfo": userinfo },
      });
    }
    if (!ir.paths.length) {
      throw new ProblemError(503, "Capacity shortfall", "No eligible endpoint is currently available for this subscription", {
        excluded: ir.excluded,
      });
    }
    const out = compile(ir, format);
    const etag = computeSubscriptionEtag({
      format,
      compiledBody: out.body,
      userinfoHeader: userinfo,
      updateIntervalHours: profileCfg.updateIntervalHours,
    });
    const metaHeaders = {
      ...HEADERS,
      etag,
      "last-modified": u.createdAt.toUTCString(),
      "subscription-userinfo": userinfo,
      "profile-update-interval": String(profileCfg.updateIntervalHours),
      ...profileMetadataHeaders({
        title: `${profileCfg.profileTitlePrefix} ${u.name}`,
        supportUrl: profileCfg.supportUrl || undefined,
        webPageUrl: profileCfg.profileWebPageUrl || undefined,
        announce: profileCfg.announce || undefined,
      }),
    };
    db.update(subscriptionTokens).set({ lastUsedAt: new Date() }).where(eq(subscriptionTokens.id, t.id)).catch(() => {});
    if (matchesIfNoneMatch(req.headers.get("if-none-match"), etag)) {
      return new Response(null, { status: 304, headers: metaHeaders });
    }
    return new Response(out.body, {
      headers: {
        ...metaHeaders,
        "content-type": out.contentType,
      },
    });
  } catch (e) {
    if (e instanceof CompileError) {
      return problemResponse(new ProblemError(500, "Compilation refused", e.message, { diagnostics: e.diagnostics }));
    }
    return problemResponse(e);
  }
}
