const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const SUPPORTED_ALGORITHMS = new Map([
  ["SHA1", "SHA-1"],
  ["SHA256", "SHA-256"],
  ["SHA512", "SHA-512"],
]);
const MIN_BASE32_LENGTH = 16;
const MAX_BASE32_LENGTH = 128;
const VALID_UNPADDED_REMAINDERS = new Set([0, 2, 4, 5, 7]);
const REQUIRED_PADDING_BY_REMAINDER = new Map([
  [0, 0],
  [2, 6],
  [4, 4],
  [5, 3],
  [7, 1],
]);

const keyCache = new Map();

function normalizeBase32(input) {
  const compact = input.toUpperCase().replace(/[\s-]/g, "");

  if (!compact) {
    throw new Error("Secret is empty");
  }

  const padding = compact.match(/=+$/)?.[0] ?? "";
  const normalized = compact.slice(0, compact.length - padding.length);

  if (normalized.includes("=")) {
    throw new Error("Base32 padding is only allowed at the end");
  }

  if ([...normalized].some((character) => !BASE32_ALPHABET.includes(character))) {
    throw new Error("Use only Base32 characters A-Z and 2-7");
  }

  if (normalized.length < MIN_BASE32_LENGTH) {
    throw new Error(`Secret is too short (minimum ${MIN_BASE32_LENGTH} characters)`);
  }

  if (normalized.length > MAX_BASE32_LENGTH) {
    throw new Error(`Secret is too long (maximum ${MAX_BASE32_LENGTH} characters)`);
  }

  const remainder = normalized.length % 8;
  if (!VALID_UNPADDED_REMAINDERS.has(remainder)) {
    throw new Error("Secret has an invalid Base32 length");
  }

  const requiredPadding = REQUIRED_PADDING_BY_REMAINDER.get(remainder);
  if (padding && padding.length !== requiredPadding) {
    throw new Error("Secret has invalid Base32 padding");
  }

  return normalized;
}

export function decodeBase32(input) {
  const normalized = normalizeBase32(input);
  const bytes = [];
  let buffer = 0;
  let bitsInBuffer = 0;

  for (const character of normalized) {
    buffer = (buffer << 5) | BASE32_ALPHABET.indexOf(character);
    bitsInBuffer += 5;

    if (bitsInBuffer >= 8) {
      bitsInBuffer -= 8;
      bytes.push((buffer >>> bitsInBuffer) & 0xff);
      buffer &= (1 << bitsInBuffer) - 1;
    }
  }

  if (buffer !== 0) {
    throw new Error("Secret has invalid Base32 padding bits");
  }

  return new Uint8Array(bytes);
}

export function parseToken(value, index = 0) {
  const raw = value.trim();

  if (!raw.toLowerCase().startsWith("otpauth://")) {
    decodeBase32(raw);
    return {
      id: `${index}:${raw}`,
      label: `Token ${index + 1}`,
      secret: raw,
      algorithm: "SHA1",
      digits: 6,
      period: 30,
    };
  }

  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("Invalid otpauth URL");
  }

  if (url.hostname.toLowerCase() !== "totp") {
    throw new Error("Only TOTP URLs are supported");
  }

  const secret = url.searchParams.get("secret")?.trim() ?? "";
  decodeBase32(secret);

  const algorithm = (url.searchParams.get("algorithm") ?? "SHA1").toUpperCase();
  if (!SUPPORTED_ALGORITHMS.has(algorithm)) {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  const digits = Number(url.searchParams.get("digits") ?? 6);
  if (!Number.isInteger(digits) || digits < 6 || digits > 8) {
    throw new Error("Digits must be between 6 and 8");
  }

  const period = Number(url.searchParams.get("period") ?? 30);
  if (!Number.isInteger(period) || period < 1 || period > 300) {
    throw new Error("Period must be between 1 and 300 seconds");
  }

  const pathLabel = decodeURIComponent(url.pathname.replace(/^\//, ""));
  const issuer = url.searchParams.get("issuer")?.trim();

  return {
    id: `${index}:${raw}`,
    label: pathLabel || issuer || `Token ${index + 1}`,
    secret,
    algorithm,
    digits,
    period,
  };
}

async function importKey(secret, algorithm) {
  const normalizedSecret = normalizeBase32(secret);
  const cacheKey = `${algorithm}:${normalizedSecret}`;

  if (!keyCache.has(cacheKey)) {
    const keyPromise = crypto.subtle.importKey(
      "raw",
      decodeBase32(normalizedSecret),
      { name: "HMAC", hash: SUPPORTED_ALGORITHMS.get(algorithm) },
      false,
      ["sign"],
    );
    keyCache.set(cacheKey, keyPromise);
  }

  return keyCache.get(cacheKey);
}

export async function generateTotp(token, timestamp = Date.now()) {
  const counter = BigInt(Math.floor(timestamp / 1000 / token.period));
  const counterBytes = new Uint8Array(8);
  new DataView(counterBytes.buffer).setBigUint64(0, counter);

  const key = await importKey(token.secret, token.algorithm);
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: "HMAC" }, key, counterBytes),
  );
  const offset = signature.at(-1) & 0x0f;
  const binary =
    (((signature[offset] & 0x7f) << 24) |
      (signature[offset + 1] << 16) |
      (signature[offset + 2] << 8) |
      signature[offset + 3]) >>>
    0;

  return String(binary % 10 ** token.digits).padStart(token.digits, "0");
}
