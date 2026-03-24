"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  clearAidCache: () => clearAidCache,
  getTrustVerdict: () => import_trust_compute.getTrustVerdict,
  verifyAidRequest: () => verifyAidRequest
});
module.exports = __toCommonJS(src_exports);
var import_crypto = require("crypto");
var import_trust_compute = require("@aidprotocol/trust-compute");
var trustCache = /* @__PURE__ */ new Map();
var MAX_CACHE_SIZE = 1e4;
function getCachedTrust(did) {
  const entry = trustCache.get(did);
  if (!entry)
    return null;
  if (Date.now() > entry.expiresAt) {
    trustCache.delete(did);
    return null;
  }
  return entry;
}
function setCachedTrust(did, score, verdict, ttlMs) {
  trustCache.set(did, { score, verdict, expiresAt: Date.now() + ttlMs });
  if (trustCache.size > MAX_CACHE_SIZE) {
    const oldest = trustCache.keys().next().value;
    if (oldest)
      trustCache.delete(oldest);
  }
}
var seenNonces = /* @__PURE__ */ new Map();
var NONCE_TTL_MS = 3e5;
function checkNonce(nonce) {
  if (seenNonces.size > 5e4) {
    const now = Date.now();
    for (const [k, v] of seenNonces) {
      if (now > v)
        seenNonces.delete(k);
    }
  }
  if (seenNonces.has(nonce)) {
    const exp = seenNonces.get(nonce);
    if (Date.now() < exp)
      return false;
    seenNonces.delete(nonce);
  }
  seenNonces.set(nonce, Date.now() + NONCE_TTL_MS);
  return true;
}
var BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58btcDecode(s) {
  const bytes = [];
  for (const c of s) {
    const idx = BASE58_ALPHABET.indexOf(c);
    if (idx < 0)
      throw new Error(`Invalid base58btc character: ${c}`);
    let carry = idx;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 255;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 255);
      carry >>= 8;
    }
  }
  for (const c of s) {
    if (c !== "1")
      break;
    bytes.push(0);
  }
  return new Uint8Array(bytes.reverse());
}
function verifyEd25519Proof(did, timestamp, nonce, method, path, bodyBytes, proof, hashAlgorithm) {
  try {
    const prefix = "did:key:z";
    if (!did.startsWith(prefix))
      return false;
    const decoded = base58btcDecode(did.slice(prefix.length));
    if (decoded.length < 34 || decoded[0] !== 237 || decoded[1] !== 1)
      return false;
    const rawPub = decoded.subarray(2);
    const spkiHeader = Buffer.from("302a300506032b6570032100", "hex");
    const spki = Buffer.concat([spkiHeader, Buffer.from(rawPub)]);
    const pubKey = (0, import_crypto.createPublicKey)({ key: spki, format: "der", type: "spki" });
    const bodyHash = (0, import_crypto.createHash)(hashAlgorithm).update(bodyBytes).digest("hex");
    const signingString = `${did}
${timestamp}
${nonce}
${method} ${path}
${bodyHash}`;
    const signatureInput = (0, import_crypto.createHash)(hashAlgorithm).update(signingString).digest();
    const sigBytes = Buffer.from(proof, "base64url");
    return (0, import_crypto.verify)(null, signatureInput, pubKey, sigBytes);
  } catch {
    return false;
  }
}
async function fetchTrust(did, apiUrl) {
  try {
    const url = `${apiUrl}/v1/aid/${encodeURIComponent(did)}/trust`;
    const res = await fetch(url, {
      method: "GET",
      headers: { "Accept": "application/json" },
      signal: AbortSignal.timeout(5e3)
    });
    if (!res.ok)
      return null;
    const data = await res.json();
    return {
      score: data.trustScore ?? data.score ?? 0,
      verdict: data.verdict ?? "new"
    };
  } catch {
    return null;
  }
}
async function verifyAidRequest(headers, method, path, bodyBytes, config = {}) {
  const {
    minTrustScore = 0,
    apiUrl = "https://api.claw-net.org",
    failMode = "closed",
    cacheTtlSeconds = 300,
    timestampToleranceSeconds = 300,
    hashAlgorithm = "sha384",
    onRejected,
    onVerified
  } = config;
  const did = headers("x-aid-did");
  if (!did) {
    return { ok: false, status: 0, error: "", code: "AID_NOT_PRESENT" };
  }
  const proof = headers("x-aid-proof");
  const timestamp = headers("x-aid-timestamp");
  const nonce = headers("x-aid-nonce");
  if (!proof || !timestamp || !nonce) {
    return {
      ok: false,
      status: 428,
      error: "X-AID-DID present but missing required headers (X-AID-PROOF, X-AID-TIMESTAMP, X-AID-NONCE)",
      code: "AID_PROOF_MISSING"
    };
  }
  const ts = new Date(timestamp).getTime();
  if (isNaN(ts) || !timestamp.endsWith("Z")) {
    return { ok: false, status: 401, error: "Invalid timestamp format (must be UTC with Z suffix)", code: "AID_SIGNATURE_INVALID" };
  }
  if (Math.abs(Date.now() - ts) > timestampToleranceSeconds * 1e3) {
    return { ok: false, status: 401, error: `Timestamp outside \xB1${timestampToleranceSeconds}s window`, code: "AID_SIGNATURE_INVALID" };
  }
  if (nonce.length !== 32 || !/^[0-9a-f]+$/i.test(nonce)) {
    return { ok: false, status: 401, error: "Invalid nonce (must be 32 hex chars)", code: "AID_SIGNATURE_INVALID" };
  }
  if (!checkNonce(nonce)) {
    return { ok: false, status: 409, error: "Nonce already used", code: "AID_NONCE_REPLAY" };
  }
  const signatureValid = verifyEd25519Proof(
    did,
    timestamp,
    nonce,
    method,
    path,
    bodyBytes,
    proof,
    hashAlgorithm
  );
  if (!signatureValid) {
    return { ok: false, status: 401, error: "Ed25519 signature verification failed", code: "AID_SIGNATURE_INVALID" };
  }
  let score = 0;
  let verdict = "new";
  let cached = false;
  const cachedEntry = getCachedTrust(did);
  if (cachedEntry) {
    score = cachedEntry.score;
    verdict = cachedEntry.verdict;
    cached = true;
  } else {
    const apiResult = await fetchTrust(did, apiUrl);
    if (apiResult) {
      score = apiResult.score;
      verdict = apiResult.verdict;
      setCachedTrust(did, score, verdict, cacheTtlSeconds * 1e3);
    } else if (failMode === "closed") {
      return { ok: false, status: 503, error: "Trust API unreachable", code: "AID_TRUST_UNAVAILABLE" };
    }
  }
  if (score < minTrustScore) {
    if (onRejected)
      onRejected(did, score, minTrustScore);
    return {
      ok: false,
      status: 403,
      error: `Trust score ${score} below minimum ${minTrustScore}`,
      code: "AID_TRUST_GATE_BLOCKED"
    };
  }
  const verdictResult = (0, import_trust_compute.getTrustVerdict)(score);
  if (onVerified)
    onVerified(did, score, verdictResult.verdict);
  return {
    ok: true,
    aidInfo: {
      did,
      trustScore: score,
      verdict: verdictResult.verdict,
      discount: verdictResult.discount,
      settlementMode: verdictResult.settlementMode,
      signatureVerified: true,
      cached
    }
  };
}
function clearAidCache() {
  trustCache.clear();
  seenNonces.clear();
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  clearAidCache,
  getTrustVerdict,
  verifyAidRequest
});
/**
 * @aidprotocol/middleware — AID trust verification for any Node.js HTTP server
 *
 * Framework-agnostic core with thin adapters for Express and Fastify.
 * Verifies Ed25519 signatures, resolves trust scores, enforces trust gates.
 *
 * @example Express
 * ```typescript
 * import express from 'express';
 * import { aidTrust } from '@aidprotocol/middleware/express';
 *
 * const app = express();
 * app.use(aidTrust({ minTrustScore: 40 }));
 *
 * app.get('/data', (req, res) => {
 *   console.log(req.aidInfo?.trustScore); // 87
 *   res.json({ ok: true });
 * });
 * ```
 *
 * @example Fastify
 * ```typescript
 * import Fastify from 'fastify';
 * import { aidTrustPlugin } from '@aidprotocol/middleware/fastify';
 *
 * const app = Fastify();
 * app.register(aidTrustPlugin, { minTrustScore: 40 });
 *
 * app.get('/data', (req, reply) => {
 *   console.log(req.aidInfo?.trustScore); // 87
 *   reply.send({ ok: true });
 * });
 * ```
 *
 * @license MIT
 */
//# sourceMappingURL=index.js.map
