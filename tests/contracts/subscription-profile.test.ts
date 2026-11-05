import assert from "node:assert/strict";
import test from "node:test";
import { profileMetadataHeaders, subscriptionUserinfo } from "../../src/lib/subscription-profile";

test("profile metadata follows encoded title and UTF-8 announce convention", () => {
  const headers = profileMetadataHeaders({
    title: "OmniPanel 用户",
    announce: "更新 available",
    supportUrl: "https://support.example/help",
    profileUrl: "https://example.test/profile",
  });
  assert.equal(headers["profile-title"], `base64:${Buffer.from("OmniPanel 用户").toString("base64")}`);
  assert.equal(headers.announce, `base64:${Buffer.from("更新 available").toString("base64")}`);
  assert.equal(headers["support-url"], "https://support.example/help");
  assert.equal(headers["profile-web-page-url"], "https://example.test/profile");
});

test("profile metadata rejects header injection and unsafe URLs", () => {
  assert.throws(() => profileMetadataHeaders({ title: "name\r\nX-Injected: yes" }), /invalid profile title/);
  assert.throws(() => profileMetadataHeaders({ title: "ok", announce: "line\nfeed" }), /invalid announce/);
  for (const supportUrl of ["http://support.example", "javascript:alert(1)", "https://u:p@example.test/"]) {
    assert.throws(() => profileMetadataHeaders({ title: "ok", supportUrl }), /invalid support URL/);
  }
});

test("userinfo inclusive expiry changes presentation only, not source date", () => {
  const expiresAt = new Date("2030-06-01T00:00:00.999Z");
  const original = expiresAt.getTime();
  const base = { uploadBytes: 10.4, downloadBytes: 20.6, quotaBytes: 100, expiresAt };
  assert.equal(subscriptionUserinfo(base), "upload=10; download=21; total=100; expire=1906502400");
  assert.equal(subscriptionUserinfo({ ...base, expiryPresentation: "inclusive" }), "upload=10; download=21; total=100; expire=1906502399");
  assert.equal(expiresAt.getTime(), original);
});

test("userinfo omits absent expiry and fails on invalid usage/date", () => {
  assert.equal(subscriptionUserinfo({ uploadBytes: 0, downloadBytes: 0, quotaBytes: null, expiresAt: null }), "upload=0; download=0; total=0");
  assert.throws(() => subscriptionUserinfo({ uploadBytes: -1, downloadBytes: 0, quotaBytes: null, expiresAt: null }), /invalid subscription usage/);
  assert.throws(() => subscriptionUserinfo({ uploadBytes: 0, downloadBytes: 0, quotaBytes: null, expiresAt: new Date(Number.NaN) }), /invalid subscription expiry/);
});
