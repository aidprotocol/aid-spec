# AID-x402 Profile

**Integration point:** HTTP headers on x402 payment flows

See Section 8.3 of the [AID Protocol Specification](../aid-protocol-v1.md) for the full profile definition.

## Headers

AID headers are additive alongside standard x402 headers:

```
# Standard x402
PAYMENT-SIGNATURE: <EIP-3009 signed authorization>

# AID trust layer (optional, enhances x402)
X-AID-DID: did:key:zABC...
X-AID-PROOF: <Ed25519 signature>
X-AID-TIMESTAMP: 2026-03-21T14:30:00Z
X-AID-NONCE: a1b2c3d4e5f6a7b8
```

## Behavior

- **Without AID headers:** Standard x402 flow (facilitator-based, base price)
- **With AID headers:** Trust-gated pricing, enhanced receipts with dual signatures
- AID headers never modify x402 semantics — they are purely additive
