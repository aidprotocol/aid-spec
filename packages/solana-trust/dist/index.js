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
  SolanaTrust: () => SolanaTrust,
  didToSolanaPubkey: () => didToSolanaPubkey,
  solanaPubkeyToDid: () => solanaPubkeyToDid
});
module.exports = __toCommonJS(src_exports);
var import_trust_compute = require("@aidprotocol/trust-compute");
var BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58Encode(bytes) {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] * 256;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let result = "";
  for (const byte of bytes) {
    if (byte !== 0)
      break;
    result += "1";
  }
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }
  return result;
}
function base58Decode(s) {
  const bytes = [];
  for (const c of s) {
    const idx = BASE58_ALPHABET.indexOf(c);
    if (idx < 0)
      throw new Error(`Invalid base58 character: ${c}`);
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
function solanaPubkeyToDid(solanaPublicKey) {
  const pubkeyBytes = base58Decode(solanaPublicKey);
  if (pubkeyBytes.length !== 32) {
    throw new Error(`Invalid Solana public key length: ${pubkeyBytes.length} (expected 32)`);
  }
  const multicodec = new Uint8Array([237, 1, ...pubkeyBytes]);
  return `did:key:z${base58Encode(multicodec)}`;
}
function didToSolanaPubkey(did) {
  if (!did.startsWith("did:key:z")) {
    throw new Error("Not a did:key DID");
  }
  const decoded = base58Decode(did.slice("did:key:z".length));
  if (decoded.length < 34 || decoded[0] !== 237 || decoded[1] !== 1) {
    throw new Error("Not an Ed25519 did:key");
  }
  return base58Encode(decoded.subarray(2));
}
var cache = /* @__PURE__ */ new Map();
function getCached(key) {
  const entry = cache.get(key);
  if (!entry)
    return null;
  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    return null;
  }
  return { ...entry.result, cached: true };
}
function setCache(key, result, ttlMs) {
  cache.set(key, { result, expiresAt: Date.now() + ttlMs });
  if (cache.size > 1e4) {
    const oldest = cache.keys().next().value;
    if (oldest)
      cache.delete(oldest);
  }
}
var SolanaTrust = class {
  apiUrl;
  cacheTtlMs;
  constructor(config = {}) {
    this.apiUrl = config.apiUrl || "https://api.claw-net.org";
    this.cacheTtlMs = (config.cacheTtlSeconds || 300) * 1e3;
  }
  /**
   * Get trust score for a Solana public key.
   */
  async getScore(solanaPublicKey) {
    const cached = getCached(solanaPublicKey);
    if (cached)
      return cached;
    let did = null;
    try {
      did = solanaPubkeyToDid(solanaPublicKey);
    } catch {
      return this.emptyResult(solanaPublicKey);
    }
    try {
      const res = await fetch(`${this.apiUrl}/v1/aid/${encodeURIComponent(did)}/trust`, {
        headers: { "Accept": "application/json" },
        signal: AbortSignal.timeout(5e3)
      });
      if (!res.ok)
        return this.emptyResult(solanaPublicKey, did);
      const data = await res.json();
      const score = data.trustScore ?? data.score ?? 0;
      const verdictResult = (0, import_trust_compute.getTrustVerdict)(score);
      const result = {
        solanaPublicKey,
        did,
        trustScore: score,
        verdict: verdictResult.verdict,
        discount: verdictResult.discount,
        cached: false,
        attestationCount: data.attestationCount ?? 0
      };
      setCache(solanaPublicKey, result, this.cacheTtlMs);
      return result;
    } catch {
      return this.emptyResult(solanaPublicKey, did);
    }
  }
  /**
   * Check if a Solana agent meets a minimum trust threshold.
   */
  async meetsThreshold(solanaPublicKey, minScore) {
    const result = await this.getScore(solanaPublicKey);
    return result.trustScore >= minScore;
  }
  /**
   * Get trust-gated price for a Solana agent.
   */
  async getTrustGatedPrice(solanaPublicKey, basePriceLamports) {
    const result = await this.getScore(solanaPublicKey);
    const adjustedPrice = Math.round(basePriceLamports * (1 - result.discount));
    return {
      originalPrice: basePriceLamports,
      adjustedPrice,
      discount: result.discount,
      verdict: result.verdict
    };
  }
  /** Clear the trust cache */
  clearCache() {
    cache.clear();
  }
  emptyResult(solanaPublicKey, did) {
    return {
      solanaPublicKey,
      did: did ?? null,
      trustScore: 0,
      verdict: "new",
      discount: 0,
      cached: false,
      attestationCount: 0
    };
  }
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  SolanaTrust,
  didToSolanaPubkey,
  solanaPubkeyToDid
});
//# sourceMappingURL=index.js.map
