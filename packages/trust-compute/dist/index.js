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
  DEFAULT_WEIGHTS: () => DEFAULT_WEIGHTS,
  FORMULA_VERSION: () => FORMULA_VERSION,
  HASH_ALGORITHM: () => HASH_ALGORITHM,
  TestSigner: () => TestSigner,
  computeTrustScore: () => computeTrustScore,
  getTrustVerdict: () => getTrustVerdict,
  jcsSerialize: () => jcsSerialize,
  verifyTrustProof: () => verifyTrustProof
});
module.exports = __toCommonJS(src_exports);
var import_crypto = require("crypto");
var HASH_ALGORITHM = "sha384";
var TestSigner = class _TestSigner {
  did;
  algorithm = "Ed25519";
  hashAlgorithm = "sha384";
  privateKey;
  publicKeyRaw;
  constructor(privateKey, publicKeyRaw) {
    this.privateKey = privateKey;
    this.publicKeyRaw = publicKeyRaw;
    const multicodec = Buffer.concat([Buffer.from([237, 1]), publicKeyRaw]);
    this.did = "did:key:z" + base58btcEncode(multicodec);
  }
  /** Generate a new random Ed25519 keypair for testing. */
  static generate() {
    const { generateKeyPairSync, createPrivateKey } = require("crypto");
    const keypair = generateKeyPairSync("ed25519");
    const privateKey = keypair.privateKey;
    const spki = keypair.publicKey.export({ type: "spki", format: "der" });
    const publicKeyRaw = spki.subarray(spki.length - 32);
    return new _TestSigner(privateKey, publicKeyRaw);
  }
  /** Create from an existing seed (deterministic for test reproducibility). */
  static fromSeed(seed) {
    const { createPrivateKey, createPublicKey } = require("crypto");
    const pkcs8Prefix = Buffer.from([
      48,
      46,
      2,
      1,
      0,
      48,
      5,
      6,
      3,
      43,
      101,
      112,
      4,
      34,
      4,
      32
    ]);
    const der = Buffer.concat([pkcs8Prefix, seed.subarray(0, 32)]);
    const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
    const publicKey = createPublicKey(privateKey);
    const spki = publicKey.export({ type: "spki", format: "der" });
    const publicKeyRaw = spki.subarray(spki.length - 32);
    return new _TestSigner(privateKey, publicKeyRaw);
  }
  async sign(canonicalBytes) {
    const { sign } = require("crypto");
    const sig = sign(null, Buffer.from(canonicalBytes), this.privateKey);
    return base64urlEncode(sig);
  }
  async verify(canonicalBytes, signature, publicKeyMultibase) {
    const { verify, createPublicKey } = require("crypto");
    const decoded = base58btcDecode(publicKeyMultibase.slice(1));
    const rawKey = decoded.subarray(2);
    const spkiPrefix = Buffer.from([
      48,
      42,
      48,
      5,
      6,
      3,
      43,
      101,
      112,
      3,
      33,
      0
    ]);
    const spki = Buffer.concat([spkiPrefix, rawKey]);
    const pubkey = createPublicKey({ key: spki, format: "der", type: "spki" });
    return verify(null, Buffer.from(canonicalBytes), pubkey, base64urlDecode(signature));
  }
  getPublicKeyMultibase() {
    const multicodec = Buffer.concat([Buffer.from([237, 1]), this.publicKeyRaw]);
    return "z" + base58btcEncode(multicodec);
  }
};
var BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58btcEncode(data) {
  let num = BigInt("0x" + data.toString("hex"));
  let result = "";
  while (num > 0n) {
    const mod = Number(num % 58n);
    result = BASE58_ALPHABET[mod] + result;
    num = num / 58n;
  }
  for (let i = 0; i < data.length && data[i] === 0; i++) {
    result = "1" + result;
  }
  return result || "1";
}
function base58btcDecode(str) {
  let num = 0n;
  for (const char of str) {
    const idx = BASE58_ALPHABET.indexOf(char);
    if (idx === -1)
      throw new Error(`Invalid base58 character: ${char}`);
    num = num * 58n + BigInt(idx);
  }
  const hex = num.toString(16).padStart(2, "0");
  const bytes = Buffer.from(hex.length % 2 ? "0" + hex : hex, "hex");
  let leadingZeros = 0;
  for (const char of str) {
    if (char !== "1")
      break;
    leadingZeros++;
  }
  return Buffer.concat([Buffer.alloc(leadingZeros), bytes]);
}
function base64urlEncode(data) {
  return data.toString("base64url");
}
function base64urlDecode(str) {
  return Buffer.from(str, "base64url");
}
var FORMULA_VERSION = "1.0.0";
var DEFAULT_WEIGHTS = {
  successRate: 40,
  chainCoverage: 25,
  volume: 20,
  manifestAdherence: 15
};
function jcsSerialize(value) {
  if (value === null)
    return "null";
  if (typeof value === "boolean")
    return value ? "true" : "false";
  if (typeof value === "number") {
    if (!isFinite(value))
      throw new Error("JCS: non-finite numbers not supported");
    return Object.is(value, -0) ? "0" : String(value);
  }
  if (typeof value === "string")
    return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(jcsSerialize).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value;
    const keys = Object.keys(obj).filter((k) => obj[k] !== void 0).sort();
    const entries = keys.map((k) => JSON.stringify(k) + ":" + jcsSerialize(obj[k]));
    return "{" + entries.join(",") + "}";
  }
  return "";
}
function computeTrustScore(stats, weights = DEFAULT_WEIGHTS) {
  const volumeScore = Math.min(stats.attestationCount / 1e3, 1);
  const manifestScore = stats.manifestAdherence > 0 || stats.attestationCount > 0 ? stats.manifestAdherence : 0.5;
  const score = Math.round(
    stats.successRate * weights.successRate + stats.chainCoverage * weights.chainCoverage + Math.min(volumeScore, 1) * weights.volume + manifestScore * weights.manifestAdherence
  );
  const clampedScore = Math.max(0, Math.min(100, score));
  const proofData = { inputs: stats, weights, score: clampedScore };
  const canonical = jcsSerialize(proofData);
  const proofHash = (0, import_crypto.createHash)(HASH_ALGORITHM).update(canonical).digest("hex");
  return {
    score: clampedScore,
    inputs: stats,
    weights,
    proofHash,
    formulaVersion: FORMULA_VERSION,
    hashAlgorithm: HASH_ALGORITHM
  };
}
function getTrustVerdict(score) {
  if (score >= 90)
    return { verdict: "proceed", discount: 0.3, settlementMode: "deferred" };
  if (score >= 80)
    return { verdict: "trusted", discount: 0.25, settlementMode: "batched" };
  if (score >= 60)
    return { verdict: "standard", discount: 0.2, settlementMode: "batched" };
  if (score >= 40)
    return { verdict: "caution", discount: 0.1, settlementMode: "standard" };
  if (score >= 20)
    return { verdict: "building", discount: 0, settlementMode: "immediate" };
  return { verdict: "new", discount: 0, settlementMode: "immediate" };
}
function verifyTrustProof(proof) {
  const recomputed = computeTrustScore(proof.inputs, proof.weights);
  return recomputed.proofHash === proof.proofHash && recomputed.score === proof.score;
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  DEFAULT_WEIGHTS,
  FORMULA_VERSION,
  HASH_ALGORITHM,
  TestSigner,
  computeTrustScore,
  getTrustVerdict,
  jcsSerialize,
  verifyTrustProof
});
/**
 * @aidprotocol/trust-compute — Standalone AID trust scoring library
 *
 * Deterministic trust score computation for AI agents.
 * No dependencies. No database. Pure computation.
 *
 * Given attestation stats, produces a trust score + cryptographic proof hash.
 * Anyone can run this to independently verify scores published by any AID oracle.
 *
 * Uses SHA-384 for proof hashes (quantum-resistant, NIST PQC migration ready).
 * Algorithm-agile: hashAlgorithm field in output enables future migration.
 *
 * @license MIT
 * @see https://claw-net.org
 */
//# sourceMappingURL=index.js.map
