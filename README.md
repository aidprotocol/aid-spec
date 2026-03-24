# AID Protocol Specification

**Agent Identity Document — The Trust Layer for Agentic Commerce**

AID is an open protocol that adds scored, verifiable, portable trust to any agent communication layer. It answers the question no other protocol addresses: *"Is this agent worth doing business with?"*

---

## What AID Provides

- **Self-certifying identity** via W3C `did:key` with pluggable key types
- **Deterministic behavioral trust scoring** from verifiable attestation history
- **Portable atomic receipts** with dual signatures and Merkle anchoring
- **Offline verification** — pure cryptography, zero network calls
- **Crypto-agile architecture** — Ed25519 today, ML-DSA (FIPS 204) tomorrow, no protocol change

## Quick Start

```javascript
// Add trust scoring to any MCP server
import { withAidTrust } from '@aidprotocol/mcp-trust';

const aid = withAidTrust(server, {
  providerDid: 'did:key:zMyDid...',
  minTrustScore: 40,
  formulaVersion: '1.0.0'
});
```

---

## Why Crypto-Agility Matters

AID launches with Ed25519 (`did:key` multicodec `0xed`) because it is fast, compact, and widely supported. But Ed25519 is not quantum-resistant. NIST has finalized post-quantum signature standards (FIPS 204 — ML-DSA, August 2024), and migration timelines are accelerating.

AID is designed so that **no protocol field, no scoring formula, and no receipt format changes** when the cryptographic primitive changes. The migration path:

| Layer | Ed25519 (today) | ML-DSA-65 (post-quantum) |
|---|---|---|
| DID method | `did:key:z6Mk...` (multicodec `0xed`) | `did:key:z...` (multicodec TBD by W3C) |
| Signature format | 64-byte Ed25519 sig | ~3,309-byte ML-DSA-65 sig |
| Trust score input | Signed attestations | Signed attestations (identical) |
| Receipt structure | Dual-signed, Merkle-anchored | Dual-signed, Merkle-anchored (identical) |
| Verification | `crypto.verify('ed25519', ...)` | `crypto.verify('ml-dsa-65', ...)` |
| Scoring formula | Unchanged | Unchanged |

### What changes

- **Key type and signature bytes.** That's it. The `did:key` method already supports multiple key types via multicodec prefix. AID reads the prefix to determine the verification algorithm. No field additions, no version bumps, no schema migration.

### What doesn't change

- Trust score computation (formula reads attestation history, not key types)
- Receipt format (signatures are opaque byte fields with algorithm identifiers)
- Merkle anchoring (hash of receipt, algorithm-independent)
- Offline verification flow (resolve DID → extract public key → verify signature)
- Scoring weights, decay curves, category mappings

### Succession protocol

When an agent migrates from Ed25519 to ML-DSA, AID's DID succession mechanism preserves trust history:

1. Agent generates new ML-DSA keypair → new `did:key`
2. Agent signs a **succession attestation**: old key signs "I am becoming `did:key:zNew...`", new key signs "I was `did:key:zOld...`"
3. Trust score, attestation history, and guardian relationships transfer to the new DID
4. Old DID enters a grace period (configurable, default 90 days) then deactivates
5. All historical receipts remain verifiable against the old key (receipts are immutable)

This means an agent can migrate to post-quantum keys **without losing its reputation** — the single hardest problem in DID rotation.

### Timeline guidance

| Period | Recommendation |
|---|---|
| Now – 2027 | Ed25519 default. Monitor NIST transition guidance. |
| 2027 – 2029 | Hybrid mode available (dual signatures for high-value receipts). |
| 2029+ | ML-DSA default. Ed25519 legacy verification retained. |

AID will publish updated test vectors for each supported algorithm as multicodec registrations are finalized.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        AID Protocol                             │
│                                                                 │
│  ┌──────────┐  ┌──────────────┐  ┌──────────┐  ┌────────────┐  │
│  │ Identity  │  │ Trust Score  │  │ Receipts │  │ Attestation│  │
│  │ (did:key) │  │ Computation  │  │ (Atomic) │  │  History   │  │
│  └─────┬────┘  └──────┬───────┘  └────┬─────┘  └─────┬──────┘  │
│        │              │               │               │         │
│        └──────────────┴───────────────┴───────────────┘         │
│                            │                                    │
│                    ┌───────┴───────┐                             │
│                    │ Merkle Anchor │                             │
│                    └───────────────┘                             │
└─────────────────────────────────────────────────────────────────┘
         │              │              │              │
    ┌────┴───┐    ┌────┴───┐    ┌────┴───┐    ┌────┴───┐
    │  MCP   │    │  A2A   │    │  x402  │    │  MPP   │
    │Profile │    │Profile │    │Profile │    │Profile │
    └────────┘    └────────┘    └────────┘    └────────┘
```

AID is **transport-agnostic**. The core protocol defines identity, scoring, receipts, and anchoring. Integration profiles adapt AID to specific communication layers without modifying the core.

### Trust Score

The trust score is a deterministic function of an agent's verifiable attestation history. Given the same attestation set, any implementation MUST produce the same score (verified via test vectors).

```
Score = Σ(weight × value × decay(age)) across attestation categories
```

- **Deterministic**: No oracles, no off-chain data, no randomness
- **Verifiable**: Any party can recompute from public attestation history
- **Decaying**: Recent behavior weighs more than historical behavior
- **Categorical**: Separate sub-scores for reliability, security, capability, responsiveness

### Atomic Receipts

Every agent-to-agent interaction can produce a receipt:

- Signed by both parties (dual-signature)
- Contains interaction metadata (no payload data)
- Hashed into a Merkle tree for batch anchoring
- Verifiable offline with only the receipt + counterparty's public key

Receipts are the raw material for trust scores. More receipts → richer attestation history → more accurate scoring.

---

## Repository Structure

```
protocols/
  aid-trust/spec.md             # Protocol 1: Identity + Trust Scoring
  aid-receipt/spec.md            # Protocol 2: Dual-Signed Receipts (DSIR)
  aid-settle/spec.md             # Protocol 3: Trust-Gated Settlement
  composability.md               # Cross-protocol composition rules

spec/
  aid-protocol-v1.md             # Full monolithic spec (reference)
  profiles/                      # 8 transport integration profiles
    aid-mcp-profile.md           # MCP integration
    aid-a2a-profile.md           # A2A integration
    aid-x402-profile.md          # x402 integration
    aid-x402-trust-extension.md  # x402 trust extension spec
    aid-mpp-profile.md           # MPP integration
    aid-erc8004-profile.md       # ERC-8004 integration
    aid-manifest-profile.md      # Manifest data profile
    aid-attestation-profile.md   # Attestation data profile

packages/                        # Published @aidprotocol packages
  trust-compute/                 # Canonical scoring library
  mcp-trust/                     # MCP server trust middleware
  middleware/                    # Express/Fastify AID verification
  aid-sdk/                       # TypeScript SDK
  solana-trust/                  # Solana Agent Registry bridge
  facilitator/                   # Open-source x402 facilitator
  x402-enhanced/                 # x402 + trust headers middleware
  trust-gate/                    # GitHub Action for CI/CD trust gates
  aid-python/                    # Python package (CrewAI/LangGraph)

test-vectors/
  signing.json                   # Ed25519 signing test vectors
  trust-score.json               # Trust score computation vectors
  merkle-proof.json              # Merkle proof verification vectors

docs/                            # Supporting documents
  governance-model.md            # Trust formula versioning
  decentralization-roadmap.md    # Progressive decentralization plan
  nist-nccoe-comment.md          # NIST NCCoE public comment
  security-harness-results.md    # Security testing results
  aid-x402-security-mapping.md   # x402 security alignment
  ara-compatibility.md           # AWS ARA compatibility
  aid-tap-reference.md           # Visa TAP reference
```

## Packages

| Package | Description | Registry |
|---|---|---|
| `@aidprotocol/trust-compute` | Deterministic trust scoring library | [npm](https://www.npmjs.com/package/@aidprotocol/trust-compute) |
| `@aidprotocol/mcp-trust` | One-line MCP server trust middleware | [npm](https://www.npmjs.com/package/@aidprotocol/mcp-trust) |
| `@aidprotocol/middleware` | Express/Fastify AID verification | [npm](https://www.npmjs.com/package/@aidprotocol/middleware) |
| `@aidprotocol/sdk` | TypeScript SDK (`AID.connect()`) | [npm](https://www.npmjs.com/package/@aidprotocol/sdk) |
| `@aidprotocol/solana-trust` | Solana Agent Registry trust bridge | [npm](https://www.npmjs.com/package/@aidprotocol/solana-trust) |
| `@aidprotocol/facilitator` | Open-source x402 facilitator (zero fees) | [npm](https://www.npmjs.com/package/@aidprotocol/facilitator) |
| `@aidprotocol/x402-enhanced` | Add trust to any x402 server | [npm](https://www.npmjs.com/package/@aidprotocol/x402-enhanced) |
| `@aidprotocol/trust-gate` | GitHub Action — CI/CD trust gate | [GitHub](https://github.com/aidprotocol/aid-spec/tree/main/packages/trust-gate) |
| `aid-trust` | Python package (CrewAI/LangGraph) | [PyPI](https://pypi.org/project/aid-trust/) |

## Standards Alignment

| Body | Status | Detail |
|---|---|---|
| **DIF TAAWG** | Submitted | Trust scoring extension for MCP-I |
| **NIST NCCoE** | Comment filed | AI Agent Standards Initiative — identity and trust |
| **W3C** | Aligned | `did:key` (DID Core v1.1), JSON Canonicalization (RFC 8785) |
| **IETF** | Aligned | HTTP Message Signatures (RFC 9421) |
| **CSA** | Mapped | Trust verdicts → Agentic Trust Framework maturity levels |
| **NIST FIPS 204** | Planned | ML-DSA support for post-quantum migration |

## Protocol Family

AID is split into three composable protocols:

| Protocol | What | Status |
|---|---|---|
| **AID-Trust** | Identity + trust scoring + Merkle verification | 1.0-draft (pre-DIF) |
| **AID-Receipt** | Dual-signed interaction receipts (DSIR) + commitment logs | 0.1-draft |
| **AID-Settle** | Trust-gated pricing + settlement modes | 0.1-draft |

AID-Trust is always required. AID-Receipt and AID-Settle are independent extensions. See [composability.md](protocols/composability.md).

**ERC-8004 Identity:** AID Protocol is registered on Base mainnet (Agent ID: 36118).

## Reference Implementation

[**ClawNet**](https://claw-net.org) is the reference implementation with production trust scoring, Merkle-anchored attestations, and 344 API endpoints.

## Security

AID assumes a hostile network. Key security properties:

- **No trust-on-first-use**: Agents must have verifiable attestation history before scoring
- **No central authority**: DIDs are self-certifying, scores are deterministic
- **Slashable guardians**: Guardians post collateral that is destroyed on failure
- **Offline-first verification**: No call home, no SPOF, no DNS dependency
- **Algorithm negotiation**: Agents advertise supported algorithms, highest common strength wins

For security vulnerabilities, see [**SECURITY.md**](./SECURITY.md).

## License

Apache 2.0 — see [**LICENSE**](./LICENSE)

## Contributing

AID is an open protocol. Contributions welcome via pull requests. The specification is intended for submission to DIF TAAWG as a work item.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.
