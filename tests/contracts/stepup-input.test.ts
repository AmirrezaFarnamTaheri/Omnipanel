import test from "node:test";
import assert from "node:assert/strict";
import { requireStepUpPassword } from "../../src/lib/stepup-input";

test("high-risk step-up requires explicit password rather than treating missing or empty input as optional", () => {
  const absent = new FormData();
  const empty = new FormData();
  empty.set("password", "");
  const wrongType = new FormData();
  wrongType.set("password", new Blob(["not-a-password"]), "upload");
  for (const form of [absent, empty, wrongType]) {
    assert.throws(() => requireStepUpPassword(form), /Step-up required/i);
  }
});

test("step-up password preserves the original secret for verification without logging or trimming it", () => {
  const form = new FormData();
  form.set("password", "  correct horse battery staple  ");
  assert.equal(requireStepUpPassword(form), "  correct horse battery staple  ");
});
