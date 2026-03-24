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
  AID: () => AID,
  default: () => src_default
});
module.exports = __toCommonJS(src_exports);
var import_crypto = require("crypto");
var import_crypto2 = require("crypto");
var import_trust_compute = require("@aidprotocol/trust-compute");
var AIDClient = class {
  did;
  privateKey;
  apiUrl;
  cacheTtl;
  trustCache = /* @__PURE__ */ new Map();
  constructor(did, privateKey, apiUrl, cacheTtl) {
    this.did = did;
    this.privateKey = privateKey;
    this.apiUrl = apiUrl;
    this.cacheTtl = cacheTtl;
  }
  sign(method, path, body) {
    const timestamp = (/* @__PURE__ */ new Date()).toISOString();
    const nonce = (0, import_crypto2.randomBytes)(16).toString("hex");
    const bodyHash = (0, import_crypto.createHash)("sha384").update(body).digest("hex");
    const signingString = `${this.did}
${timestamp}
${nonce}
${method} ${path}
${bodyHash}`;
    const signatureInput = (0, import_crypto.createHash)("sha384").update(signingString).digest();
    const signature = (0, import_crypto.sign)(null, signatureInput, this.privateKey).toString("base64url");
    return {
      "X-AID-DID": this.did,
      "X-AID-PROOF": signature,
      "X-AID-TIMESTAMP": timestamp,
      "X-AID-NONCE": nonce
    };
  }
  async query(skillId, variables) {
    const path = `/v1/skills/${encodeURIComponent(skillId)}/invoke`;
    const body = JSON.stringify({ variables: variables || {} });
    const headers = this.sign("POST", path, body);
    const res = await fetch(`${this.apiUrl}${path}`, {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/json" },
      body,
      signal: AbortSignal.timeout(3e4)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || `AID query failed: ${res.status}`);
    }
    return res.json();
  }
  async getTrust() {
    return this.lookupTrust(this.did);
  }
  async lookupTrust(did) {
    const cached = this.trustCache.get(did);
    if (cached && Date.now() < cached.expiresAt)
      return cached.info;
    const res = await fetch(`${this.apiUrl}/v1/aid/${encodeURIComponent(did)}/trust`, {
      headers: { "Accept": "application/json" },
      signal: AbortSignal.timeout(5e3)
    });
    if (!res.ok) {
      return { did, score: 0, verdict: "new", attestationCount: 0, discount: 0, settlementMode: "immediate" };
    }
    const data = await res.json();
    const score = data.trustScore ?? data.score ?? 0;
    const verdictResult = (0, import_trust_compute.getTrustVerdict)(score);
    const info = {
      did,
      score,
      verdict: verdictResult.verdict,
      attestationCount: data.attestationCount ?? 0,
      discount: verdictResult.discount,
      settlementMode: verdictResult.settlementMode
    };
    this.trustCache.set(did, { info, expiresAt: Date.now() + this.cacheTtl * 1e3 });
    return info;
  }
  async feedback(receiptId, outcome, qualityScore) {
    const path = "/aid/feedback";
    const body = JSON.stringify({ receiptId, outcome, qualityScore });
    const headers = this.sign("POST", path, body);
    const res = await fetch(`${this.apiUrl}${path}`, {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/json" },
      body,
      signal: AbortSignal.timeout(5e3)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || `Feedback failed: ${res.status}`);
    }
  }
  async heartbeat() {
    const res = await fetch(`${this.apiUrl}/aid/heartbeat`, {
      headers: { "Accept": "application/json" },
      signal: AbortSignal.timeout(5e3)
    });
    return res.json();
  }
};
async function connect(config = {}) {
  const apiUrl = config.apiUrl || "https://api.claw-net.org";
  const cacheTtl = config.cacheTtlSeconds || 300;
  if (config.privateKeySeed) {
    const seed2 = Buffer.from(config.privateKeySeed, "hex");
    if (seed2.length !== 32)
      throw new Error("privateKeySeed must be 64 hex chars (32 bytes)");
    const pkcs8Header2 = Buffer.from("302e020100300506032b657004220420", "hex");
    const pkcs8Der2 = Buffer.concat([pkcs8Header2, seed2]);
    const privateKey2 = (0, import_crypto.createPrivateKey)({ key: pkcs8Der2, format: "der", type: "pkcs8" });
    const pubKey = require("crypto").createPublicKey(privateKey2);
    const spki = pubKey.export({ type: "spki", format: "der" });
    const rawPub = spki.subarray(12);
    const multicodec = Buffer.concat([Buffer.from([237, 1]), rawPub]);
    const did = `did:key:z${base58btcEncode(multicodec)}`;
    return new AIDClient(did, privateKey2, apiUrl, cacheTtl);
  }
  const name = config.name || `agent-${(0, import_crypto2.randomBytes)(4).toString("hex")}`;
  const res = await fetch(`${apiUrl}/aid/provision`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-AID-NEW": name },
    body: JSON.stringify({ name }),
    signal: AbortSignal.timeout(1e4)
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || `AID provisioning failed: ${res.status}`);
  }
  const data = await res.json();
  const seed = Buffer.from(data.privateKeySeed, "hex");
  const pkcs8Header = Buffer.from("302e020100300506032b657004220420", "hex");
  const pkcs8Der = Buffer.concat([pkcs8Header, seed]);
  const privateKey = (0, import_crypto.createPrivateKey)({ key: pkcs8Der, format: "der", type: "pkcs8" });
  return new AIDClient(data.did, privateKey, apiUrl, cacheTtl);
}
var B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58btcEncode(bytes) {
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
    result += B58_ALPHABET[digits[i]];
  }
  return result;
}
var AID = { connect };
var src_default = AID;
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  AID
});
//# sourceMappingURL=index.js.map
