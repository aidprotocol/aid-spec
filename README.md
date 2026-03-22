# AID Protocol Specification

**Agent Identity Document — The Trust Layer for Agentic Commerce**

AID is an open protocol that adds scored, verifiable, portable trust to any agent communication layer. It answers the question no other protocol addresses: *"Is this agent worth doing business with?"*

## What AID Provides

- **Self-certifying identity** via W3C `did:key` (Ed25519)
- **Deterministic behavioral trust scoring** from verifiable attestation history
- **Portable atomic receipts** with dual signatures and Merkle anchoring
- **Offline verification** — pure cryptography, zero network calls
- **Crypto-agile architecture** — designed for NIST post-quantum migration

## Quick Start

```typescript
// Add trust scoring to any MCP server
import { withAidTrust } from '@aidprotocol/mcp-trust';

const aid = withAidTrust(server, {
  providerDid: 'did:key:zMyDid...',
  minTrustScore: 40,
  formulaVersion: '1.0.0'
});
```

## Repository Structure

```
spec/
  aid-protocol-v1.md          # The specification
  profiles/
    aid-mcp-profile.md         # MCP integration profile
    aid-a2a-profile.md         # A2A integration profile
    aid-x402-profile.md        # x402 integration profile
    aid-mpp-profile.md         # MPP integration profile
test-vectors/
  signing.json                 # Ed25519 signing test vectors
  trust-score.json             # Trust score computation vectors
  merkle-proof.json            # Merkle proof verification vectors
reference/
  (minimal reference implementation)
docs/
  nist-nccoe-comment.md        # NIST NCCoE public comment
```

## Packages

| Package | Description | npm |
|---------|-------------|-----|
| `@aidprotocol/trust-compute` | Standalone trust scoring library | [![npm](https://img.shields.io/npm/v/@aidprotocol/trust-compute)](https://www.npmjs.com/package/@aidprotocol/trust-compute) |
| `@aidprotocol/mcp-trust` | MCP server trust middleware | [![npm](https://img.shields.io/npm/v/@aidprotocol/mcp-trust)](https://www.npmjs.com/package/@aidprotocol/mcp-trust) |

## Standards Alignment

- **DIF TAAWG** — Submitted as trust scoring extension for MCP-I
- **NIST NCCoE** — Comment submitted on AI Agent Standards Initiative
- **W3C** — Uses `did:key` (DID Core v1.1), JSON Canonicalization (RFC 8785)
- **IETF** — HTTP Message Signatures aligned (RFC 9421)
- **CSA** — Trust verdicts map to Agentic Trust Framework maturity levels

## Reference Implementation

[ClawNet](https://claw-net.org) is the reference implementation with production trust scoring, Merkle-anchored attestations, and 344 API endpoints.

## License

Apache 2.0 — see [LICENSE](LICENSE)

## Contributing

AID is an open protocol. Contributions welcome via pull requests. The specification is intended for submission to DIF as a TAAWG work item.

For security vulnerabilities, see [SECURITY.md](SECURITY.md).
