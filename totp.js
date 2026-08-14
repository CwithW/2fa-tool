const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const SUPPORTED_ALGORITHMS = new Map([
  ["SHA1", "SHA-1"],
  ["SHA256", "SHA-256"],
  ["SHA512", "SHA-512"],
]);

const keyCache = new Map();

export function decodeBase32(input) {
  const normalized = input
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/=+$/, "");

  if (!normalized) {
    throw new Error("Secret is empty");
  }

  if ([...normalized].some((character) => !BASE32_ALPHABET.includes(character))) {
    throw new Error("Secret is not valid Base32");
  }

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
  const normalizedSecret = secret.toUpperCase().replace(/[\s-]/g, "").replace(/=+$/, "");
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
