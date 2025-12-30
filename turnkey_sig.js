import http from 'k6/http';
import { check } from 'k6';
import { Trend } from 'k6/metrics';
import secrets from 'k6/secrets';
import encoding from 'k6/encoding';

const latency = new Trend('turnkey_sig_latency');
const MESSAGE  = "HELLO FROM TURNKEY HQ. How fast _are you_ today?";


// --- Helpers ---------------------------------------------------------------

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

function hexToBytes(hex) {
  let h = hex.trim().toLowerCase().replace(/^0x/, '');
  if (h.length % 2) h = '0' + h;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function leftPadTo32(bytes) {
  if (bytes.length > 32) throw new Error('Private key >32 bytes');
  if (bytes.length === 32) return bytes;
  const out = new Uint8Array(32);
  out.set(bytes, 32 - bytes.length);
  return out;
}

function derLen(n) {
  if (n < 128) return Uint8Array.of(n);
  const bytes = [];
  while (n > 0) { bytes.unshift(n & 0xff); n >>= 8; }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function derSequence(content) {
  return Uint8Array.of(0x30, ...derLen(content.length), ...content);
}

function derOctetString(bytes) {
  return Uint8Array.of(0x04, ...derLen(bytes.length), ...bytes);
}

function buildPkcs8FromRawP256(dHex) {
  const d = leftPadTo32(hexToBytes(dHex));

  // ECPrivateKey (RFC 5915): SEQUENCE { version=1, privateKey OCTET STRING(32) }
  const ecPriv = derSequence(
    Uint8Array.of(
      0x02, 0x01, 0x01,              // INTEGER 1
      0x04, 0x20, ...d               // OCTET STRING(32) = d
    )
  );

  // AlgorithmIdentifier = SEQUENCE( oid ecPublicKey, oid prime256v1 )
  //   ecPublicKey: 1.2.840.10045.2.1  => 06 07 2A 86 48 CE 3D 02 01
  //   prime256v1: 1.2.840.10045.3.1.7 => 06 08 2A 86 48 CE 3D 03 01 07
  const algId = Uint8Array.of(
    0x30, 0x13,
      0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
      0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
  );

  // PrivateKeyInfo (PKCS#8):
  // SEQUENCE { version=0, algorithm AlgId, privateKey OCTET STRING(ecPriv) }
  const pki = derSequence(
    Uint8Array.of(
      0x02, 0x01, 0x00,              // INTEGER 0
      ...algId,
      ...derOctetString(ecPriv)
    )
  );

  return pki.buffer; // ArrayBuffer for crypto.subtle.importKey('pkcs8', ...)
}

// Bytes -> hex string
function bytesToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// Minimal ASN.1 DER encoder for ECDSA r|s -> DER sequence
function rsToDer(rs) {
  // rs is Uint8Array length 64 (P-256)
  function trimLeadingZeros(a) {
    let i = 0;
    while (i < a.length - 1 && a[i] === 0) i++;
    return a.slice(i);
  }
  function toDerInteger(a) {
    a = trimLeadingZeros(a);
    if (a[0] & 0x80) a = Uint8Array.of(0x00, ...a); // ensure positive
    return Uint8Array.of(0x02, a.length, ...a);
  }
  const r = toDerInteger(rs.slice(0, 32));
  const s = toDerInteger(rs.slice(32));
  const len = r.length + s.length;
  return Uint8Array.of(0x30, len, ...r, ...s);
}

// Build X-Stamp header value from body bytes using API key (P-256)
async function makeXStamp(bodyBytes) {
  const apiPrivHex = await secrets.get('turnkey-api-private-key');
  const apiPubHex  = await secrets.get('turnkey-api-public-key'); // compressed SEC1 hex

  if (!apiPrivHex || !apiPubHex) {
    throw new Error('Missing secrets: API public key or private key is not set correctly');
  }
  const pkcs8 = buildPkcs8FromRawP256(apiPrivHex);

  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );

  // WebCrypto returns raw r|s; Turnkey expects DER-encoded signature in hex for the stamp
  const sigRaw = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, bodyBytes)
  );
  const sigDerHex = bytesToHex(rsToDer(sigRaw));

  const stamp = JSON.stringify({
    publicKey: apiPubHex,
    signature: sigDerHex,
    scheme: 'SIGNATURE_SCHEME_TK_API_P256'
  });

  // Base64URL without padding is what docs call “Base64URL”
  return encoding.b64encode(stamp, 'rawurl');
}

export default async function () {
  const TURNKEY_ORGANIZATION_ID = await secrets.get('turnkey-organization-id');
  const TURNKEY_SIGN_WITH = await secrets.get('turnkey-sign-with')

  const url = `https://api.turnkey.com/public/v1/submit/sign_raw_payload`;
  const payload = JSON.stringify({
    type: "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2",
    timestampMs: new Date().getTime().toString(),
    organizationId: TURNKEY_ORGANIZATION_ID,
    parameters: {
      signWith: TURNKEY_SIGN_WITH,
      payload: MESSAGE,
      encoding: "PAYLOAD_ENCODING_TEXT_UTF8",
      hashFunction: "HASH_FUNCTION_NOT_APPLICABLE",
    },
  });

  const payloadBytes = utf8Bytes(payload);
  const xStamp = await makeXStamp(payloadBytes);

  const res = http.post(url, payload, {
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'X-Stamp': xStamp
    },
  });

  latency.add(res.timings.duration);

  check(res, {
    'status is 200': (r) => {
      if (r.status !== 200) {
        console.error("bad status detected", r.status);
      }
      return r.status === 200
    },
    'activity completed': (r) => {
      try {
        const completed = r.json('activity.status') === 'ACTIVITY_STATUS_COMPLETED';
        if (!completed) {
          console.error("activity is not complete!", r.json())
        }
        return completed
      } catch { return false; }
    }
  });
}
