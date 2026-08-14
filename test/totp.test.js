import { webcrypto } from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";

import { decodeBase32, generateTotp, parseToken } from "../totp.js";

globalThis.crypto ??= webcrypto;

test("decodes Base32 secrets", () => {
  const decoded = decodeBase32("JBSW Y3DP-EHPK3PXP");
  assert.deepEqual(
    [...decoded],
    [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef],
  );
});

test("matches the RFC 6238 SHA-1 test vector", async () => {
  const token = {
    secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    algorithm: "SHA1",
    digits: 8,
    period: 30,
  };

  assert.equal(await generateTotp(token, 59_000), "94287082");
});

test("parses otpauth TOTP settings", () => {
  const token = parseToken(
    "otpauth://totp/Example:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=45",
  );

  assert.deepEqual(
    {
      label: token.label,
      algorithm: token.algorithm,
      digits: token.digits,
      period: token.period,
    },
    {
      label: "Example:alice@example.com",
      algorithm: "SHA256",
      digits: 8,
      period: 45,
    },
  );
});

test("rejects invalid Base32", () => {
  assert.throws(() => parseToken("invalid0secret"), /Base32/);
});
