# AID Protocol Test Vectors

Canonical test vectors for verifying AID implementations.

## Files

| File | Description |
|------|-------------|
| `signing.json` | Ed25519 signing input construction + verification |
| `trust-score.json` | Trust score computation with proof hashes |
| `merkle-proof.json` | Merkle proof generation and verification |

## Usage

These test vectors are also available in the `@aidprotocol/trust-compute` package test suite. Run:

```bash
npm install @aidprotocol/trust-compute
npm test
```

## Format

Each test vector file contains an array of test cases:

```json
{
  "testCases": [
    {
      "description": "what this tests",
      "inputs": { ... },
      "expected": { ... }
    }
  ]
}
```

Implementations MUST produce identical outputs for identical inputs. If your implementation produces different results from these vectors, it is not AID-compatible.
