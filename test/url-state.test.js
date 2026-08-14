import test from "node:test";
import assert from "node:assert/strict";

import { buildTokenUrl, readTokensFromFragment } from "../url-state.js";

test("stores tokens in the fragment and removes legacy query tokens", () => {
  const url = buildTokenUrl("https://example.com/app?theme=dark&token=legacy", [
    "FIRSTSECRET",
    "SECONDSECRET",
  ]);

  assert.equal(url.search, "?theme=dark");
  assert.deepEqual(readTokensFromFragment(url.hash), ["FIRSTSECRET", "SECONDSECRET"]);
  assert.match(url.href, /#token=/);
});

test("round-trips an otpauth URL without placing it in the request", () => {
  const token =
    "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
  const url = buildTokenUrl("https://example.com/tool", [token]);

  assert.equal(url.search, "");
  assert.equal(readTokensFromFragment(url.hash)[0], token);
});
