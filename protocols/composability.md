# AID Protocol Composability

> Cross-protocol requirements for the AID family.
> Defines how AID-Trust, AID-Receipt, and AID-Settle interact.
> Each protocol works standalone. This doc defines how they compose.

## Protocol Dependency Graph

```
AID-Trust (required)
    ↑
AID-Receipt (optional, extends AID-Trust)
    ↑
AID-Settle (optional, extends AID-Trust, benefits from AID-Receipt)
```

AID-Trust is always required. AID-Receipt and AID-Settle are independent extensions — you can implement AID-Settle without AID-Receipt (using platform attestations instead of DSIRs), though the trust signal is weaker.

## Cross-Protocol Design Decisions

### 1. Heartbeat Extensibility

AID-Trust owns `GET /aid/heartbeat` with a base schema. Other protocols extend via the `extensions` object:

```json
{
  "provider": { },
  "services": [ ],
  "protocolVersion": "1.0",
  "extensions": {
    "aidReceipt": {
      "supportedFormats": ["dsir-v1"],
      "commitmentLogEndpoint": "/v1/aid/{did}/commitment-log"
    },
    "aidSettle": {
      "pricingTiers": [ ],
      "settlementModes": ["immediate", "batched", "deferred"],
      "paymentChains": ["base", "solana"],
      "recipient": "0x..."
    }
  }
}
```

Implementations MUST ignore unknown extension keys. New protocols can add extensions without breaking existing parsers.

### 2. Trust Tier Table Split

**AID-Trust defines:** score range → verdict mapping.

| Score Range | Verdict |
|-------------|---------|
| 0-19 | `new` |
| 20-39 | `building` |
| 40-59 | `caution` |
| 60-79 | `standard` |
| 80-89 | `trusted` |
| 90+ (gated) | `proceed` |

**AID-Settle defines:** verdict → settlement mode + pricing.

| Verdict | Settlement Mode | Pricing |
|---------|----------------|---------|
| `new` | `immediate` | Base price |
| `building` | `immediate` | Base price |
| `caution` | `standard` | 10% discount |
| `standard` | `batched` | 20% discount |
| `trusted` | `batched` | 25% discount |
| `proceed` | `deferred` | 30% discount |

AID-Trust's spec contains NO settlement concepts. AID-Settle's spec references verdicts by name without duplicating the scoring formula.

### 3. Merkle Anchoring Chain Requirement

Trust score Merkle roots (AID-Trust) and receipt commitment log Merkle roots (AID-Receipt) MUST anchor to the SAME chain. Cross-referencing requires reading one chain, not two.

The canonical anchor chain is specified in `/.well-known/aid.json` under `"anchorChain"`. Both protocols read this value.

### 4. /.well-known/aid.json Extensibility

AID-Trust owns the base document. Other protocols add sections:

```json
{
  "version": "1.0",
  "anchorChain": "base",
  "trustVectorSupported": true,
  "signatureAlgorithm": "Ed25519",
  "hashAlgorithm": "SHA-256",
  "extensions": {
    "aidReceipt": {
      "dsirVersion": "1.0",
      "commitmentLogFormat": "merkle-sha256"
    },
    "aidSettle": {
      "paymentChains": ["base"],
      "settlementModes": ["immediate", "batched"]
    }
  }
}
```

### 5. Transport Profiles (Cross-Protocol)

One profile per transport, covering ALL active protocols. Not three separate profiles.

- `profiles/mcp.md` — how AID-Trust, AID-Receipt, and AID-Settle work over MCP transport
- `profiles/a2a.md` — how the AID family works in A2A agent cards
- `profiles/x402.md` — how the AID family composes with x402 payment headers

Each profile describes which protocols are relevant for that transport and how they're expressed.

### 6. Avoid Flag Handoff

**AID-Trust** defines the `avoid` flag:
- What it is (manual flag from validators or structured reports)
- How it's set (quorum of 3 validators with trust > 60)
- How it propagates (WebSocket broadcast within 30 seconds)

**AID-Settle** defines the avoid flag's EFFECTS:
- Prepay only (no batched/deferred)
- Base price (no discounts)
- Feedback weight = 0

Both specs reference this handoff. AID-Trust's spec says "for settlement effects, see AID-Settle." AID-Settle's spec says "for flag governance, see AID-Trust."

### 7. Trust Input Hierarchy (Abstract → Concrete Mapping)

**AID-Trust** defines abstract input classes:

| Input Class | Weight |
|-------------|--------|
| Bilateral verified interactions | 1.0 |
| Bilateral disputed interactions | 0.3 |
| Unilateral attested with evidence | 0.5 |
| External oracle data | 0.3 |
| Self-declared inputs | 0.1 |

**AID-Receipt** maps concrete constructs to these classes:

| AID-Receipt Construct | Maps To | Weight |
|----------------------|---------|--------|
| Agreed DSIRs (both parties match) | Bilateral verified | 1.0 |
| Disputed DSIRs (parties disagree) | Bilateral disputed | 0.3 |
| Attestations with receipt reference | Unilateral attested | 0.5 |

This design means AID-Trust's scoring formula works without AID-Receipt — it just runs on weaker input data (platform attestations at 0.5 weight instead of DSIRs at 1.0).
