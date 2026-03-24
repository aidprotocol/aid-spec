"use strict";

// src/index.ts
async function run() {
  const did = process.env.INPUT_DID || "";
  const minScore = parseInt(process.env["INPUT_MIN-SCORE"] || "40", 10);
  const apiUrl = process.env["INPUT_API-URL"] || "https://api.claw-net.org";
  const failOnError = (process.env["INPUT_FAIL-ON-ERROR"] || "true") === "true";
  if (!did) {
    setFailed('Input "did" is required');
    return;
  }
  if (!did.startsWith("did:")) {
    setFailed(`Invalid DID format: ${did}`);
    return;
  }
  console.log(`\u{1F50D} Checking AID trust score for ${did}`);
  console.log(`   Minimum required: ${minScore}`);
  console.log(`   API: ${apiUrl}`);
  try {
    const url = `${apiUrl}/v1/aid/${encodeURIComponent(did)}/trust`;
    const res = await fetch(url, {
      method: "GET",
      headers: { "Accept": "application/json", "User-Agent": "aidprotocol/trust-gate" },
      signal: AbortSignal.timeout(1e4)
    });
    if (!res.ok) {
      const msg = `Trust API returned ${res.status}: ${res.statusText}`;
      if (failOnError) {
        setFailed(msg);
      } else {
        console.log(`\u26A0\uFE0F  ${msg} \u2014 continuing (fail-on-error: false)`);
        setOutput("passed", "false");
        setOutput("score", "0");
        setOutput("verdict", "unknown");
      }
      return;
    }
    const data = await res.json();
    const score = data.trustScore ?? data.score ?? 0;
    const verdict = data.verdict ?? "new";
    const attestationCount = data.attestationCount ?? 0;
    setOutput("score", String(score));
    setOutput("verdict", verdict);
    setOutput("attestation-count", String(attestationCount));
    const passed = score >= minScore;
    setOutput("passed", String(passed));
    if (passed) {
      console.log(`\u2705 Trust gate PASSED \u2014 score: ${score} (${verdict}), attestations: ${attestationCount}`);
    } else {
      const msg = `Trust gate FAILED \u2014 score: ${score} (${verdict}) < minimum ${minScore}`;
      console.log(`\u274C ${msg}`);
      setFailed(msg);
    }
  } catch (err) {
    const msg = `Trust API error: ${err.message || err}`;
    if (failOnError) {
      setFailed(msg);
    } else {
      console.log(`\u26A0\uFE0F  ${msg} \u2014 continuing (fail-on-error: false)`);
      setOutput("passed", "false");
      setOutput("score", "0");
      setOutput("verdict", "unknown");
    }
  }
}
function setOutput(name, value) {
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) {
    const fs = require("fs");
    fs.appendFileSync(outputFile, `${name}=${value}
`);
  }
  console.log(`  ::set-output name=${name}::${value}`);
}
function setFailed(message) {
  console.log(`::error::${message}`);
  process.exitCode = 1;
}
run();
