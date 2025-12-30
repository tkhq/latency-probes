import http from "k6/http";
import { check } from "k6";
import { Trend } from "k6/metrics";
import secrets from "k6/secrets";
import encoding, { b64decode } from "k6/encoding";

const latency = new Trend("cdp_sig_latency");

const CDP_HOST = "api.cdp.coinbase.com";

// UTF-8 encode a JS string → Uint8Array
// This is because k6 doesn't support TextEncoder...
function utf8Bytes(str) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    let cp = str.charCodeAt(i);

    // handle surrogate pairs
    if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < str.length) {
      const next = str.charCodeAt(++i);
      if (next >= 0xdc00 && next <= 0xdfff) {
        cp = ((cp - 0xd800) << 10) + (next - 0xdc00) + 0x10000;
      } else {
        // unmatched high surrogate: back up
        i--;
      }
    }

    if (cp <= 0x7f) out.push(cp);
    else if (cp <= 0x7ff) {
      out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
    } else if (cp <= 0xffff) {
      out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    } else {
      out.push(
        0xf0 | (cp >> 18),
        0x80 | ((cp >> 12) & 0x3f),
        0x80 | ((cp >> 6) & 0x3f),
        0x80 | (cp & 0x3f)
      );
    }
  }
  return new Uint8Array(out);
}

/**
 * Base64url encode (RFC 7515)
 */
function b64url(inputBytes) {
  const b64 = encoding.b64encode(inputBytes);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

/**
 * decode PEM body -> Uint8Array (inner bytes)
 */
function pemToBytes(pem) {
  const lines = pem.trim().split("\\n");
  const b64 = lines
    .filter((l) => !l.startsWith("-----BEGIN") && !l.startsWith("-----END"))
    .join("");
  const buf = encoding.b64decode(b64, "std"); // returns an ArrayBuffer
  //return new Uint8Array(buf.split("").map((c) => c.charCodeAt(0)));
  return new Uint8Array(buf);
}

function arrayBufferToHex(buf) {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

// Helper to encode the right DER bytes for length (needs to be canonical)
function derLen(n) {
  if (n < 0x80) return Uint8Array.of(n);
  // minimal long-form
  const bytes = [];
  while (n > 0) { bytes.unshift(n & 0xff); n >>= 8; }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function tlv(tag, value) {
  const L = derLen(value.length);
  const out = new Uint8Array(1 + L.length + value.length);
  out[0] = tag;
  out.set(L, 1);
  out.set(value, 1 + L.length);
  return out;
}

function concat(...arrs) {
  const len = arrs.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

// Hardcoded PKCS#8 wrapper for EC P-256 private keys
// This has to be done because CDP API private keys are SEC1 encoded and not PKCS8-encoded.
// SUCH a PITA.
function sec1DerToPkcs8(sec1Der) {
  // AlgorithmIdentifier = SEQUENCE( OID ecPublicKey, OID prime256v1 )
  const algId = tlv(0x30, concat(
    tlv(0x06, Uint8Array.of(0x2a,0x86,0x48,0xce,0x3d,0x02,0x01)),       // 1.2.840.10045.2.1
    tlv(0x06, Uint8Array.of(0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07))    // 1.2.840.10045.3.1.7
  ));

  const version0 = tlv(0x02, Uint8Array.of(0x00));          // INTEGER 0
  const privKey  = tlv(0x04, sec1Der);                      // OCTET STRING (SEC1)

  // PrivateKeyInfo = SEQUENCE( version, algId, privateKey )
  return tlv(0x30, concat(version0, algId, privKey));
}

async function importEs256PrivateKey(pemEncodedKey) {
  // P256 API Private keys from CDP are SEC-1 encoded, but wallet secrets are pkcs8-encoded.
  // Go figure. This is madness.
  // Here we sort out which is which based on the PEM header.
  const isSec1 = (pemEncodedKey || "").includes("BEGIN EC PRIVATE KEY");

  var pkcs8Bytes;

  if (isSec1) {
    const sec1Bytes = pemToBytes(pemEncodedKey);
    pkcs8Bytes = sec1DerToPkcs8(sec1Bytes);
  } else {
    pkcs8Bytes = pemToBytes(pemEncodedKey);
  }

  return crypto.subtle.importKey(
    "pkcs8",
    pkcs8Bytes.buffer,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
}

async function signEs256(key, signingInputBytes) {
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, signingInputBytes)
  );

  if (sig.length === 64) {
    return sig;
  } else {
    throw new Error(`Unexpected ES256 signature length: ${sig.length}`);
  }
}

function nonce() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return arrayBufferToHex(bytes.buffer);
}

/**
 * Build a JWT for CDP.
 *
 * CDP SDK docs mention an 'uris' claim (omitted for websocket JWTs). :contentReference[oaicite:2]{index=2}
 * We set:
 * - header: { alg: ES256, typ: JWT, kid: <apiKeyId> }
 * - payload: standard time claims + uris: ["<METHOD> <HOST><PATH>"]
 *
 * NOTE: CDP’s exact required claims are defined in their auth docs; if you get 401,
 * the first thing to tweak is the payload shape (iss/sub/aud/uris format).
 */
async function makeBearerJwt({ apiKeyId, apiKeySecretPemPkcs8, method, host, path, expiresInSec = 120 }) {
  const now = Math.floor(Date.now() / 1000);
  const n = nonce();
  console.log("generated nonce", n);

  const header = {
    alg: "ES256",
    typ: "JWT",
    kid: apiKeyId,
    nonce: n,
  };

  const payload = {
    iss: "cdp",
    sub: apiKeyId,
    iat: now,
    nbf: now,
    exp: now + expiresInSec,
    uris: [`${method.toUpperCase()} ${host}${path}`],
  };

  const encodedHeader = b64url(utf8Bytes(JSON.stringify(header)));
  const encodedPayload = b64url(utf8Bytes(JSON.stringify(payload)));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const key = await importEs256PrivateKey(apiKeySecretPemPkcs8);
  const sigJose = await signEs256(key, utf8Bytes(signingInput));
  const encodedSig = b64url(sigJose);

  return `${signingInput}.${encodedSig}`;
}

/**
 * Wallet-auth JWT. CDP requires X-Wallet-Auth for signing endpoints. :contentReference[oaicite:3]{index=3}
 *
 * The SDK API suggests wallet JWT generation depends on requestMethod/host/path AND requestData. :contentReference[oaicite:4]{index=4}
 * We include requestData in the payload to mirror that intent.
 */
async function makeWalletJwt({ walletSecretPemPkcs8, method, host, path, requestData, expiresInSec = 120 }) {
  const now = Math.floor(Date.now() / 1000);

  const header = {
    alg: "ES256",
    typ: "JWT",
  };

  const requestHashBytes = await crypto.subtle.digest("SHA-256", utf8Bytes(requestData));

  const payload = {
    iat: now,
    nbf: now,
    jti: nonce(),
    uris: [`${method.toUpperCase()} ${host}${path}`],
    requestData: requestData,
    reqHash: arrayBufferToHex(requestHashBytes),
  };

  const encodedHeader = b64url(utf8Bytes(JSON.stringify(header)));
  const encodedPayload = b64url(utf8Bytes(JSON.stringify(payload)));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const key = await importEs256PrivateKey(walletSecretPemPkcs8);
  const sigJose = await signEs256(key, utf8Bytes(signingInput));
  const encodedSig = b64url(sigJose);

  return `${signingInput}.${encodedSig}`;
}

export default async function () {
  // These are the CDP API Key ID and secret
  // (see https://docs.cdp.coinbase.com/api-reference/v2/authentication#1-create-secret-api-key)
  // This is used to build the Bearer token for the request
  const CDP_API_KEY_ID = await secrets.get("cdp-api-key-id");
  const CDP_API_KEY_SECRET = await secrets.get("cdp-api-key-secret");

  // Wallet secret (PKCS#8 PEM) used for X-Wallet-Auth header
  const CDP_WALLET_SECRET = await secrets.get("cdp-wallet-secret");

  // The account address to sign with (must be SOL since we are using /platform/v2/solana/... below)
  const ADDRESS = await secrets.get("cdp-sign-with");

  const path = `/platform/v2/solana/accounts/${ADDRESS}/sign/message`;
  const url = `https://${CDP_HOST}${path}`;

  const body = {
    message: "HELLO FROM TURNKEY HQ. How fast _are you_ today?"
  }
  const bodyStr = JSON.stringify(body);

  // Bearer token for this exact request
  const bearer = await makeBearerJwt({
    apiKeyId: CDP_API_KEY_ID,
    apiKeySecretPemPkcs8: CDP_API_KEY_SECRET,
    method: "POST",
    host: CDP_HOST,
    path,
    expiresInSec: 120, // SDK docs default to 120s
  });

  // Wallet token for this exact request (include request body as requestData)
  const walletAuth = await makeWalletJwt({
    walletSecretPemPkcs8: CDP_WALLET_SECRET,
    method: "POST",
    host: CDP_HOST,
    path,
    requestData: bodyStr,
    expiresInSec: 120,
  });

  const headers = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${bearer}`,
    "X-Wallet-Auth": walletAuth,
  };

  const res = http.post(url, bodyStr, { headers });
  console.log("response", res.status, res.error, res.body);
  latency.add(res.timings.duration);

  check(res, {
    "status 200": (r) => r.status === 200,
    "has signature": (r) => !!r.json("signature"),
    "signature is valid base64 encoding": (r) => {
      const sigDecoded = b64decode(r.json("signature"));
      const hexSig = arrayBufferToHex(sigDecoded);
      console.log("decoded signature length", sigDecoded.length);
      return hexSig.length >= 128; // at least 32 bytes * 2 hex chars/byte
    },
  });
}
