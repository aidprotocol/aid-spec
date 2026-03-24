// src/index.ts
var DEFAULT_TIERS = [
  { minTrust: 90, multiplier: 0.7, verdict: "proceed" },
  { minTrust: 80, multiplier: 0.75, verdict: "trusted" },
  { minTrust: 60, multiplier: 0.8, verdict: "standard" },
  { minTrust: 40, multiplier: 0.9, verdict: "caution" },
  { minTrust: 20, multiplier: 1, verdict: "building" },
  { minTrust: 0, multiplier: 1, verdict: "new" }
];
var cache = /* @__PURE__ */ new Map();
var MAX_CACHE = 1e4;
function getCached(did) {
  const entry = cache.get(did);
  if (!entry)
    return null;
  if (Date.now() > entry.expiresAt) {
    cache.delete(did);
    return null;
  }
  return entry.score;
}
function setCache(did, score, ttlMs) {
  cache.set(did, { score, expiresAt: Date.now() + ttlMs });
  if (cache.size > MAX_CACHE) {
    const oldest = cache.keys().next().value;
    if (oldest)
      cache.delete(oldest);
  }
}
async function fetchTrustScore(did, apiUrl) {
  try {
    const res = await fetch(`${apiUrl}/v1/aid/${encodeURIComponent(did)}/trust`, {
      headers: { "Accept": "application/json" },
      signal: AbortSignal.timeout(5e3)
    });
    if (!res.ok)
      return null;
    const data = await res.json();
    return data.trustScore ?? data.score ?? 0;
  } catch {
    return null;
  }
}
function withAidTrust(config) {
  const {
    basePriceUsd,
    recipientAddress,
    chain = "base",
    apiUrl = "https://api.claw-net.org",
    cacheTtlSeconds = 300,
    pricingTiers = DEFAULT_TIERS,
    onTrustPriced
  } = config;
  const cacheTtlMs = cacheTtlSeconds * 1e3;
  const sortedTiers = [...pricingTiers].sort((a, b) => b.minTrust - a.minTrust);
  function getMultiplier(score) {
    for (const tier of sortedTiers) {
      if (score >= tier.minTrust) {
        return { multiplier: tier.multiplier, verdict: tier.verdict };
      }
    }
    return { multiplier: 1, verdict: "new" };
  }
  return {
    /**
     * Check a request for AID trust headers and compute trust-gated pricing.
     *
     * @param headers - Request headers (object or function)
     * @returns Trust check result with adjusted pricing
     */
    async checkRequest(headers) {
      const getHeader = typeof headers === "function" ? headers : (name) => {
        const val = headers[name] ?? headers[name.toLowerCase()];
        return Array.isArray(val) ? val[0] : val;
      };
      const did = getHeader("X-AID-DID") || getHeader("x-aid-did");
      if (!did) {
        return {
          trustVerified: false,
          did: null,
          trustScore: 0,
          verdict: "new",
          basePriceUsd,
          adjustedPriceUsd: basePriceUsd,
          discountPct: 0,
          paymentRequired: buildPaymentRequired(basePriceUsd, recipientAddress, chain),
          cached: false
        };
      }
      let score;
      let cached = false;
      const cachedScore = getCached(did);
      if (cachedScore !== null) {
        score = cachedScore;
        cached = true;
      } else {
        const apiScore = await fetchTrustScore(did, apiUrl);
        score = apiScore ?? 0;
        setCache(did, score, cacheTtlMs);
      }
      const { multiplier, verdict } = getMultiplier(score);
      const adjustedPriceUsd = Number((basePriceUsd * multiplier).toFixed(6));
      const discountPct = Math.round((1 - multiplier) * 100);
      if (onTrustPriced) {
        onTrustPriced(did, basePriceUsd, adjustedPriceUsd, verdict);
      }
      return {
        trustVerified: true,
        did,
        trustScore: score,
        verdict,
        basePriceUsd,
        adjustedPriceUsd,
        discountPct,
        paymentRequired: buildPaymentRequired(adjustedPriceUsd, recipientAddress, chain),
        cached
      };
    },
    /** Generate x402 402 response headers with trust-gated pricing */
    build402Headers(result) {
      const headers = {
        "PAYMENT-REQUIRED": result.paymentRequired
      };
      if (result.trustVerified) {
        headers["X-AID-TRUST-GATE"] = `min_score=0,tier=${result.verdict}`;
        headers["X-AID-PRICING-TIERS"] = JSON.stringify(
          sortedTiers.map((t) => ({
            min: t.minTrust,
            price: (basePriceUsd * t.multiplier).toFixed(6),
            verdict: t.verdict
          }))
        );
      }
      return headers;
    },
    /** Clear the trust score cache */
    clearCache() {
      cache.clear();
    },
    /** Get current config */
    config: { basePriceUsd, recipientAddress, chain, tiers: sortedTiers }
  };
}
function buildPaymentRequired(priceUsd, recipient, chain) {
  return Buffer.from(JSON.stringify({
    amount: priceUsd.toFixed(6),
    currency: "USDC",
    chain,
    recipient,
    protocol: "x402",
    aidEnhanced: true
  })).toString("base64");
}
export {
  withAidTrust
};
/**
 * @aidprotocol/x402-enhanced — Add AID trust to any x402 server
 *
 * Wraps x402 payment middleware with AID trust verification.
 * Agents with higher trust scores pay less via trust-gated pricing.
 *
 * @example
 * ```typescript
 * import { createServer } from 'http';
 * import { withAidTrust } from '@aidprotocol/x402-enhanced';
 *
 * const aid = withAidTrust({
 *   basePriceUsd: 0.001,       // base price per request
 *   recipientAddress: '0x...',  // your USDC address
 * });
 *
 * createServer(async (req, res) => {
 *   const result = await aid.checkRequest(req);
 *
 *   if (result.trustVerified) {
 *     // Agent has AID — apply trust-gated pricing
 *     console.log(result.adjustedPrice); // discounted price
 *   }
 *
 *   // Serve the resource
 *   res.end(JSON.stringify({ data: '...' }));
 * }).listen(3000);
 * ```
 *
 * @license MIT
 */
//# sourceMappingURL=index.mjs.map
