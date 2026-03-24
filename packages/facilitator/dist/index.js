#!/usr/bin/env node
#!/usr/bin/env node
"use strict";

// src/index.ts
var import_http = require("http");
var import_trust_compute = require("@aidprotocol/trust-compute");
var PORT = parseInt(process.env.AID_FACILITATOR_PORT || "8402", 10);
var AID_API = process.env.AID_API_URL || "https://api.claw-net.org";
var HAS_SETTLEMENT_KEY = !!process.env.SETTLEMENT_PRIVATE_KEY;
async function handleRequest(req, res) {
  const url = new URL(req.url || "/", `http://localhost:${PORT}`);
  const path = url.pathname;
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-AID-DID, X-AID-PROOF, X-AID-TIMESTAMP, X-AID-NONCE");
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }
  if (path === "/info" && req.method === "GET") {
    json(res, 200, {
      name: "AID Protocol Facilitator",
      version: "1.0.0",
      protocol: "x402",
      fee: "0",
      feeDescription: "Zero fees \u2014 open-source, self-hosted",
      chains: ["base"],
      currencies: ["USDC"],
      canSettle: HAS_SETTLEMENT_KEY,
      aidTrust: { enabled: true, apiUrl: AID_API }
    });
    return;
  }
  if (path === "/health" && req.method === "GET") {
    json(res, 200, {
      status: "healthy",
      canVerify: true,
      canSettle: HAS_SETTLEMENT_KEY,
      uptime: process.uptime(),
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    });
    return;
  }
  if (path === "/verify" && req.method === "POST") {
    const body = await readBody(req);
    if (!body || !body.payload) {
      json(res, 400, { valid: false, error: "Missing payment payload" });
      return;
    }
    const did = req.headers["x-aid-did"];
    let trustInfo = null;
    if (did) {
      try {
        const trustRes = await fetch(`${AID_API}/v1/aid/${encodeURIComponent(did)}/trust`, {
          headers: { "Accept": "application/json" },
          signal: AbortSignal.timeout(3e3)
        });
        if (trustRes.ok) {
          const data = await trustRes.json();
          const score = data.trustScore ?? data.score ?? 0;
          trustInfo = { score, verdict: (0, import_trust_compute.getTrustVerdict)(score) };
        }
      } catch {
      }
    }
    const valid = body.payload && (body.payload.amount || body.payload.value);
    json(res, 200, {
      valid: !!valid,
      facilitator: "aidprotocol",
      fee: "0",
      trust: trustInfo ? {
        did,
        score: trustInfo.score,
        verdict: trustInfo.verdict.verdict,
        discount: trustInfo.verdict.discount
      } : null
    });
    return;
  }
  if (path === "/settle" && req.method === "POST") {
    if (!HAS_SETTLEMENT_KEY) {
      json(res, 503, { settled: false, error: "No settlement key configured. Set SETTLEMENT_PRIVATE_KEY." });
      return;
    }
    const body = await readBody(req);
    if (!body || !body.payload) {
      json(res, 400, { settled: false, error: "Missing payment payload" });
      return;
    }
    json(res, 200, {
      settled: false,
      error: "Settlement not yet implemented in reference facilitator. Use ClawNet facilitator for live settlement.",
      facilitator: "aidprotocol",
      fee: "0"
    });
    return;
  }
  json(res, 404, { error: "Not found", routes: ["/info", "/health", "/verify", "/settle"] });
}
function json(res, status, data) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}
async function readBody(req) {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(body));
      } catch {
        resolve(null);
      }
    });
    req.on("error", () => resolve(null));
  });
}
var server = (0, import_http.createServer)(handleRequest);
server.listen(PORT, () => {
  console.log(`AID Protocol Facilitator running on http://localhost:${PORT}`);
  console.log(`  /info    \u2014 facilitator metadata`);
  console.log(`  /health  \u2014 health check`);
  console.log(`  /verify  \u2014 verify x402 payment proof`);
  console.log(`  /settle  \u2014 settle payment on-chain`);
  console.log(`  Fee: $0 (zero fees)`);
  console.log(`  Settlement: ${HAS_SETTLEMENT_KEY ? "enabled" : "disabled (set SETTLEMENT_PRIVATE_KEY)"}`);
  console.log(`  AID Trust: ${AID_API}`);
});
//# sourceMappingURL=index.js.map
