# AID-Trust Protocol Specification

> Version: 1.0-draft
> Status: Pre-DIF submission
> Protocol 1 of the AID family

Trust scoring + identity + verification for agent commerce. Five headers. One formula. Merkle verification. Offline-verifiable.

*Full spec to be extracted from internal engineering docs. This is a placeholder for the public protocol structure.*

## Scope

AID-Trust defines:
- Self-certifying identity (Ed25519 did:key)
- Trust scoring formula (v1.0: 4 dimensions, v1.1: 5 dimensions)
- Merkle-anchored trust snapshots
- Heartbeat protocol (base — extensible by AID-Receipt and AID-Settle)
- Mutual authentication (X-AID-PROOF + X-AID-PROVIDER-PROOF)
- Trust verdicts (new / building / caution / standard / trusted / proceed)
- Anti-gaming mechanisms
- Key rotation + identity lifecycle
- Error semantics (10 AID_* error codes)
- Conformance Level 1 (Core) and Level 2 (Trust)

AID-Trust does NOT define:
- Receipt formats (see AID-Receipt)
- Feedback endpoint (see AID-Receipt — requires receiptId)
- Settlement modes or pricing discounts (see AID-Settle)
- Guardian agents, insurance, social graph (ClawNet product features)

## Composability

AID-Trust is designed to work standalone or composed with AID-Receipt and AID-Settle. See `protocols/composability.md` for cross-protocol requirements.

## Trust Input Hierarchy (Abstract)

AID-Trust defines input classes abstractly so the formula works without AID-Receipt:

| Input Class | Weight | Example |
|-------------|--------|---------|
| Bilateral verified interactions | 1.0 | (mapped by AID-Receipt: agreed DSIRs) |
| Unilateral attested interactions | 0.5 | Platform attestations with evidence |
| External oracle data | 0.3 | ERC-8004, Cred, third-party scores |
| Self-declared inputs | 0.1 | Manifest claims, capability declarations |

The composability doc maps AID-Receipt constructs to these abstract classes.

## Heartbeat (Base)

AID-Trust owns `GET /aid/heartbeat` with a base schema. AID-Receipt and AID-Settle extend it via optional sections:

```json
{
  "provider": { },
  "services": [ ],
  "stats": { },
  "timestamp": "",
  "protocolVersion": "",
  "extensions": {
    "aidReceipt": { },
    "aidSettle": { }
  }
}
```

## Trust Verdicts (Score → Verdict Only)

AID-Trust defines the score-to-verdict mapping:

| Score Range | Verdict |
|-------------|---------|
| 0-19 | `new` |
| 20-39 | `building` |
| 40-59 | `caution` |
| 60-79 | `standard` |
| 80-89 | `trusted` |
| 90+ (with verification + age + revenue gates) | `proceed` |

Settlement modes and pricing discounts are defined by AID-Settle, not AID-Trust.
