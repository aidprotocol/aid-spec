# AID-A2A Profile

**Integration point:** A2A agent card `extensions` field

See Section 8.2 of the [AID Protocol Specification](../aid-protocol-v1.md) for the full profile definition.

## Agent Card Extension

```json
{
  "extensions": {
    "aidTrust": {
      "did": "did:key:zABC...",
      "trustScore": 87,
      "trustVerdict": "proceed",
      "verified": true,
      "attestationCount": 1247,
      "merkleRoot": "sha256:9c4d...",
      "heartbeatUrl": "https://api.example.com/aid/heartbeat",
      "trustTimestamp": "2026-03-21T14:00:00Z",
      "trustProof": "<Ed25519 signature>"
    }
  }
}
```

## Requirements

- `trustProof` MUST be verified against the platform's public key at `/.well-known/aid-platform-key`
- Trust data older than 24 hours SHOULD be re-fetched from the `heartbeatUrl`
