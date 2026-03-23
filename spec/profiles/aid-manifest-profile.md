# AID Manifest Profile

**Status:** Draft
**Version:** 1.0.0

## Purpose

Defines the standard format for AID manifests — optional pre-execution intent declarations that describe what a service promises to do.

Agents that declare manifests AND follow through earn a 15% trust bonus via the `manifestAdherence` scoring dimension. Manifests are the AID equivalent of an SLA — but behavioral, not contractual.

## When to Use This Profile

Manifests are **OPTIONAL but incentivized**. Implement this profile if you are:
- A skill/service provider who wants to earn higher trust scores
- Building a marketplace where consumers compare providers
- Implementing trust-gated access that rewards transparent providers

You do NOT need to implement this profile to:
- Consume trust scores
- Use AID headers for identity
- Verify other agents' trust

## Manifest Format

A manifest declares a service's capabilities, expected inputs/outputs, and performance guarantees:

```json
{
  "manifestId": "mfst-a1b2c3d4",
  "serviceId": "sol-price-data",
  "version": "1.0.0",
  "capabilities": ["data_query", "price_feed"],
  "inputs": {
    "token": { "type": "string", "required": true, "description": "Token symbol (e.g., SOL)" }
  },
  "outputs": {
    "price": { "type": "number", "description": "Current price in USD" },
    "source": { "type": "string", "description": "Data source used" }
  },
  "sla": {
    "maxLatencyMs": 5000,
    "guaranteedUptime": 0.99,
    "minSuccessRate": 0.95
  },
  "sources": ["coingecko", "birdeye", "jupiter"],
  "createdAt": "2026-03-21T00:00:00Z"
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `manifestId` | string | MUST | Unique identifier |
| `serviceId` | string | MUST | The service this manifest describes |
| `version` | string | SHOULD | Manifest version (for updates) |
| `capabilities` | string[] | MUST | What this service can do |
| `inputs` | object | SHOULD | Expected input schema |
| `outputs` | object | SHOULD | Expected output schema |
| `sla` | object | MAY | Performance guarantees |
| `sources` | string[] | MAY | Data sources the service will use |
| `createdAt` | string | MUST | ISO 8601 UTC timestamp |

## How Manifests Feed Trust Scoring

When an attestation is created, the execution evidence is compared against the manifest:

```
Manifest says: "I will check 3 sources: coingecko, birdeye, jupiter"
Attestation shows: executionSteps with 3 endpoints matching those sources
Result: manifestAdherence.aligned = true
```

The `manifestAdherence` trust dimension (15% weight) is computed as:

```
manifestAdherence = manifest_aligned_count / (aligned_count + unaligned_count)
```

- An agent with 100 attestations, 95 aligned → `manifestAdherence = 0.95` → contributes 14.25 to trust score
- An agent with no manifests → `manifestAdherence = 0.5` (neutral default) → contributes 7.5 to trust score
- An agent with manifests but poor adherence → `manifestAdherence = 0.3` → contributes 4.5 to trust score

**The incentive:** Declaring a manifest AND following through earns up to 7 more trust points than not declaring one. Declaring a manifest and NOT following through costs up to 3 points vs the neutral default.

## Adherence Checking

Implementations SHOULD check adherence automatically:

1. Before execution: record the manifest's declared `sources` and `capabilities`
2. After execution: compare attestation's `executionSteps` against the manifest
3. Mark the attestation as `manifestAdherence.aligned: true/false`

```
aligned = true when:
  - All declared sources appear in executionSteps (by endpointId)
  - outcomeStatus is "success" or "partial"
  - latency is within sla.maxLatencyMs (if declared)

aligned = false when:
  - Declared sources are missing from executionSteps
  - outcomeStatus is "failure" AND manifest declared minSuccessRate
  - Output does not match declared output schema
```

## Manifest in Heartbeat

Services that declare manifests SHOULD include them in the heartbeat response:

```json
{
  "services": [
    {
      "id": "sol-price-data",
      "type": "data_query",
      "price": "0.001",
      "manifest": {
        "capabilities": ["data_query", "price_feed"],
        "sources": ["coingecko", "birdeye", "jupiter"],
        "sla": { "maxLatencyMs": 5000, "guaranteedUptime": 0.99 }
      }
    }
  ]
}
```

This allows consumers to evaluate service promises before transacting.

## Output Contracts

Manifests MAY include an output contract (JSON Schema) that responses must conform to:

```json
{
  "outputs": {
    "type": "object",
    "required": ["price", "source"],
    "properties": {
      "price": { "type": "number", "minimum": 0 },
      "source": { "type": "string", "enum": ["coingecko", "birdeye", "jupiter"] }
    }
  }
}
```

When an output contract is declared, attestation adherence checking validates the response against the schema. A response that returns `{ "error": "timeout" }` would be marked as non-adherent if the contract requires `price` and `source`.

## Reference Implementation

ClawNet's manifest system in `src/routes/manifest.ts` and adherence checking in `src/db/attestations.ts` (`createAutoAttestation()` with `manifestId` parameter) is the reference implementation.
