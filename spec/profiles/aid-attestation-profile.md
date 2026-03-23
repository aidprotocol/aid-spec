# AID Attestation Profile

**Status:** Draft
**Version:** 1.0.0

## Purpose

Defines the standard format for AID attestation records — the data that feeds trust score computation.

An attestation is a **single atomic record** that captures both the execution evidence (what steps were taken) and the outcome (success/failure). Any platform producing attestations in this format can feed any AID-compatible trust oracle.

## When to Use This Profile

Implement this profile if you are:
- Building an AID trust oracle (you need to consume attestation data)
- Building an AID-compatible platform (you need to produce attestation data)
- Bridging trust data between platforms (you need a common format)

This profile is OPTIONAL for platforms that only consume trust scores. If you only call `GET /v1/aid/:did/trust` to look up scores, you do not need to implement this profile.

## Attestation Record Format

Every attestation MUST include these fields:

```json
{
  "attestationId": "att-a1b2c3d4",
  "sequenceNumber": 248,
  "agentDid": "did:key:zABC...",
  "actionType": "skill_invoke",
  "actionEndpoint": "POST /v1/skills/sol-price/invoke",
  "outcomeStatus": "success",
  "inputHash": "<sha384 hex of request payload>",
  "responseHash": "<sha384 hex of response payload>",
  "creditsCharged": 1.5,
  "durationMs": 230,
  "prevAttestationHash": "<sha384 hex of previous attestation>",
  "signature": "<HMAC-SHA384 or Ed25519 signature>",
  "hashAlgorithm": "sha384",
  "createdAt": "2026-03-21T14:30:02Z"
}
```

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `attestationId` | string | Unique identifier (implementation-defined format) |
| `sequenceNumber` | integer | Monotonically increasing per agent. Gap detection + replay protection |
| `agentDid` | string | DID of the agent this attestation is for |
| `actionType` | string | What was done (e.g., `skill_invoke`, `data_query`, `orchestrate`, `llm_prompt`) |
| `outcomeStatus` | enum | `success`, `partial`, or `failure` |
| `inputHash` | string | SHA-384 hex digest of the request payload. Content-addressed — proves what was requested without revealing it |
| `responseHash` | string | SHA-384 hex digest of the response payload |
| `creditsCharged` | number | Cost of this transaction |
| `durationMs` | integer | Execution time in milliseconds |
| `prevAttestationHash` | string | SHA-384 of the previous attestation record. Creates a tamper-evident hash chain |
| `signature` | string | HMAC-SHA384 or Ed25519 signature over the attestation content |
| `hashAlgorithm` | string | Hash algorithm used (MUST be `sha384` for v1.0) |
| `createdAt` | string | ISO 8601 UTC timestamp |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `actionEndpoint` | string | The specific endpoint called |
| `executionSteps` | array | Step-level execution evidence (see below) |
| `manifestAdherence` | object | Whether execution matched the declared manifest |

## Execution Evidence

When `executionSteps` is present, the attestation includes step-level proof of work:

```json
{
  "executionSteps": [
    {
      "endpointId": "coingecko-price",
      "success": true,
      "cached": false,
      "durationMs": 85,
      "cost": 0.15
    },
    {
      "endpointId": "birdeye-price",
      "success": true,
      "cached": false,
      "durationMs": 120,
      "cost": 0.15
    }
  ],
  "sourceHashes": [
    { "source": "coingecko-price", "hash": "<sha384>", "fetchedAt": "2026-03-21T14:30:00Z" },
    { "source": "birdeye-price", "hash": "<sha384>", "fetchedAt": "2026-03-21T14:30:01Z" }
  ],
  "executionSummary": {
    "totalSteps": 2,
    "successfulSteps": 2,
    "cachedSteps": 0,
    "totalLatencyMs": 205,
    "proofHash": "<sha384 of step data>"
  }
}
```

Each step is individually hashed so that:
- The number of steps is verifiable (claimed 3 sources → proof shows 3 hashes)
- Each step's success/failure is independently recorded
- Cached steps are distinguished from live calls

The `proofHash` is `SHA-384(JCS(steps))` — deterministic, verifiable by anyone with the step data.

## Execution Steps (Field Definitions)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `endpointId` | string | MUST | Identifier of the endpoint or service called |
| `success` | boolean | MUST | Whether this step succeeded |
| `cached` | boolean | MUST | Whether the result was served from cache |
| `durationMs` | integer | MUST | Time taken for this step |
| `cost` | number | SHOULD | Credit cost for this step |

## Hash Chain

Attestations form a tamper-evident chain via `prevAttestationHash`:

```
att-001 (prevHash: "000...000")
  ↓ SHA-384(att-001)
att-002 (prevHash: hash of att-001)
  ↓ SHA-384(att-002)
att-003 (prevHash: hash of att-002)
```

Modifying any historical attestation invalidates all subsequent hashes. This is the `chainCoverage` dimension in trust scoring (25% weight).

The first attestation for a new agent uses `prevAttestationHash: "0" × 96` (96 zero hex chars = SHA-384 length).

## How Attestations Feed Trust Scoring

AID trust scoring (Section 3 of the core spec) consumes attestation data as follows:

| Trust Dimension | Weight | Derived From |
|----------------|--------|-------------|
| `successRate` | 40% | `success_count / total_attestations` |
| `chainCoverage` | 25% | Fraction of attestations with valid hash-chain links |
| `volume` | 20% | `min(total_attestations / 1000, 1)` |
| `manifestAdherence` | 15% | `manifest_aligned / (aligned + unaligned)` |

Implementations aggregate these stats from the attestation records. The scoring formula is defined in the core spec and the `@aidprotocol/trust-compute` library.

## Interoperability

Any platform can produce AID-compatible attestations by following this format. The attestation data can be:
- Stored in any database (SQL, NoSQL, on-chain, IPFS)
- Transmitted via any transport (HTTP, WebSocket, message queue)
- Verified by any party with the signing key

The only requirement is that the format matches this profile so that any AID trust oracle can consume it.

## Reference Implementation

ClawNet's `createAutoAttestation()` in `src/db/attestations.ts` is the reference implementation. It automatically captures execution steps from the request pipeline and produces attestation records in this format.

## npm Package

`@aidprotocol/trust-compute` — includes `verifyTrustProof()` for verifying that a trust score was correctly computed from attestation data.
