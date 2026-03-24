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
  computeTrustScore: () => import_trust_compute.computeTrustScore,
  getTrustVerdict: () => import_trust_compute.getTrustVerdict,
  verifyTrustProof: () => import_trust_compute.verifyTrustProof,
  withAidTrust: () => withAidTrust
});
module.exports = __toCommonJS(src_exports);
var import_trust_compute = require("@aidprotocol/trust-compute");
var TrustCache = class {
  cache = /* @__PURE__ */ new Map();
  ttlMs;
  constructor(ttlSeconds) {
    this.ttlMs = ttlSeconds * 1e3;
  }
  get(did) {
    const entry = this.cache.get(did);
    if (!entry)
      return null;
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(did);
      return null;
    }
    return { ...entry.trust, cached: true };
  }
  set(did, trust) {
    this.cache.set(did, {
      trust,
      expiresAt: Date.now() + this.ttlMs
    });
    if (this.cache.size > 1e4) {
      const oldest = this.cache.keys().next().value;
      if (oldest)
        this.cache.delete(oldest);
    }
  }
  clear() {
    this.cache.clear();
  }
};
async function fetchTrustFromApi(did, apiUrl) {
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
      verdict: data.verdict ?? "new",
      attestationCount: data.attestationCount ?? 0
    };
  } catch {
    return null;
  }
}
function withAidTrust(server, config) {
  const {
    providerDid,
    minTrustScore = 0,
    apiUrl = "https://api.claw-net.org",
    failMode = "closed",
    cacheTtlSeconds = 300,
    onRejected,
    onVerified
  } = config;
  const cache = new TrustCache(cacheTtlSeconds);
  const requestTrust = /* @__PURE__ */ new WeakMap();
  async function resolveTrust(did) {
    const cached = cache.get(did);
    if (cached)
      return cached;
    const apiResult = await fetchTrustFromApi(did, apiUrl);
    if (!apiResult) {
      if (failMode === "closed")
        return null;
      const fallback = {
        did,
        score: 0,
        verdict: "new",
        discount: 0,
        settlementMode: "immediate",
        cached: false,
        resolvedAt: (/* @__PURE__ */ new Date()).toISOString()
      };
      return fallback;
    }
    const verdictResult = (0, import_trust_compute.getTrustVerdict)(apiResult.score);
    const trust = {
      did,
      score: apiResult.score,
      verdict: verdictResult.verdict,
      discount: verdictResult.discount,
      settlementMode: verdictResult.settlementMode,
      cached: false,
      resolvedAt: (/* @__PURE__ */ new Date()).toISOString()
    };
    cache.set(did, trust);
    if (onVerified) {
      onVerified(did, trust.score, trust.verdict);
    }
    return trust;
  }
  const originalTool = server.tool.bind(server);
  server.tool = function wrappedTool(name, ...args) {
    const handlerIndex = args.findIndex((a) => typeof a === "function");
    if (handlerIndex === -1) {
      return originalTool(name, ...args);
    }
    const originalHandler = args[handlerIndex];
    args[handlerIndex] = async function trustedHandler(params, extra) {
      let callerDid = null;
      if (extra?.meta?.["X-AID-DID"]) {
        callerDid = extra.meta["X-AID-DID"];
      } else if (extra?.sessionId) {
        callerDid = `session:${extra.sessionId}`;
      }
      if (callerDid && callerDid.startsWith("did:")) {
        const trust = await resolveTrust(callerDid);
        if (!trust) {
          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                error: "Trust verification failed",
                code: "AID_TRUST_UNAVAILABLE",
                detail: "Could not verify caller trust score. Try again later."
              })
            }],
            isError: true
          };
        }
        if (trust.score < minTrustScore) {
          if (onRejected)
            onRejected(callerDid, trust.score, minTrustScore);
          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                error: "Trust score too low",
                code: "AID_TRUST_GATE_BLOCKED",
                callerScore: trust.score,
                requiredScore: minTrustScore,
                verdict: trust.verdict,
                detail: `Minimum trust score ${minTrustScore} required. Your score: ${trust.score} (${trust.verdict}).`
              })
            }],
            isError: true
          };
        }
        if (extra && typeof extra === "object") {
          requestTrust.set(extra, trust);
        }
      }
      return originalHandler(params, extra);
    };
    return originalTool(name, ...args);
  };
  return {
    getCallerTrust(extra) {
      if (!extra || typeof extra !== "object")
        return null;
      return requestTrust.get(extra) ?? null;
    },
    resolveTrust,
    async meetsThreshold(did) {
      const trust = await resolveTrust(did);
      return trust !== null && trust.score >= minTrustScore;
    },
    provider: { did: providerDid, minTrustScore },
    clearCache() {
      cache.clear();
    }
  };
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  computeTrustScore,
  getTrustVerdict,
  verifyTrustProof,
  withAidTrust
});
/**
 * @aidprotocol/mcp-trust — Trust verification middleware for MCP servers
 *
 * Add trust scoring to any MCP server in one line.
 * Verifies caller identity via Ed25519 signatures, resolves trust scores,
 * and makes trust data available in every tool handler.
 *
 * @example
 * ```typescript
 * import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
 * import { withAidTrust } from '@aidprotocol/mcp-trust';
 *
 * const server = new McpServer({ name: 'my-api' });
 *
 * const aid = withAidTrust(server, {
 *   providerDid: 'did:key:zMyServerDid...',
 *   minTrustScore: 40,
 *   apiUrl: 'https://api.claw-net.org',
 * });
 *
 * // Trust data available in tool context
 * server.tool('get-data', { query: z.string() }, async (params, extra) => {
 *   const trust = aid.getCallerTrust(extra);
 *   console.log(trust?.score); // 87
 *   return { content: [{ type: 'text', text: 'result' }] };
 * });
 * ```
 *
 * @license MIT
 */
//# sourceMappingURL=index.js.map
