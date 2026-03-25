# AID-Trust Protocol Specification

**Version:** 1.0-draft
**Status:** Pre-DIF submission
**Protocol:** 1 of 3 in the AID family
**License:** Apache 2.0

---

## Conformance

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 1. Abstract

AID-Trust defines self-certifying identity, deterministic trust scoring, and offline verification for AI agents. It is the foundational protocol of the AID family — AID-Receipt and AID-Settle extend it but are not required.

AID-Trust answers: *"Is this agent worth doing business with?"*

**What AID-Trust defines:**
- Self-certifying identity via W3C `did:key` (Ed25519)
- Deterministic trust scoring formula (4 dimensions, verifiable proof hash)
- Merkle-anchored trust snapshots (offline verification)
- HTTP headers for mutual authentication
- Heartbeat protocol (service discovery, extensible)
- Trust verdicts (score → verdict mapping)
- Anti-gaming mechanisms (decay, diversity, weighted feedback)
- Key rotation and identity lifecycle
- Error semantics (5 AID_* error codes)
- Privacy model (public verdicts, owner-only scores)

**What AID-Trust does NOT define:**
- Receipt formats (see AID-Receipt)
- Feedback endpoint (see AID-Receipt — requires receiptId)
- Settlement modes or pricing discounts (see AID-Settle)
- Guardian agents, insurance, social graph (implementation features)

**Reference implementation:** [ClawNet](https://claw-net.org)
**Scoring library:** [`@aidprotocol/trust-compute`](https://www.npmjs.com/package/@aidprotocol/trust-compute) (npm, MIT)

---

## 2. Design Principles

1. **Trust is computed, not declared.** Scores derive from verifiable attestation history, not self-reported claims.
2. **Identity is self-certifying.** The public key IS the identifier. No registry lookup required.
3. **Verification is offline.** Ed25519 signatures + Merkle proofs = pure math, zero network calls.
4. **Algorithm-agile.** Every document includes `signatureAlgorithm`, `algorithmVersion`, `hashAlgorithm`. Never hardcode Ed25519 or SHA-256.
5. **Complementary, not competitive.** AID plugs into existing protocols (MCP, A2A, x402, ACP, UCP).
6. **Transparent.** The scoring formula is published, open-source, and independently verifiable.
7. **Progressive decentralization.** The reference implementation is centralized, but the architecture is designed so any component can be independently verified, challenged, or replaced.

---

## 3. Identity

### 3.1 DID Method

AID uses the W3C `did:key` method with Ed25519 (multicodec `0xed`):

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

The public key is encoded directly in the DID using multibase base58btc with the Ed25519 multikey prefix (`0xed 0x01`). Identity is self-certifying: the DID encodes the public key, so verification requires no registry lookup.

**DID resolution:**
1. Strip the `did:key:` prefix.
2. Decode the remaining base58btc string (multibase prefix `z`).
3. Strip the 2-byte multicodec prefix (`0xed 0x01`).
4. The remaining 32 bytes are the raw Ed25519 public key.

### 3.2 Agent Identity Document

Every agent has an AID document:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://aid.claw-net.org/contexts/v1"
  ],
  "id": "did:key:z6Mk...",
  "type": "AgentIdentityDocument",
  "version": "1.0.0",
  "signatureAlgorithm": "EdDSA",
  "algorithmVersion": "1.0",
  "hashAlgorithm": "sha256",
  "agent": {
    "displayName": "my-trading-bot",
    "agentType": "autonomous",
    "createdAt": "2026-03-21T10:00:00Z"
  },
  "publicKey": {
    "type": "Ed25519VerificationKey2020",
    "publicKeyMultibase": "z6Mk..."
  },
  "trustScore": {
    "score": 79,
    "inputs": {
      "successRate": 0.95,
      "chainCoverage": 0.88,
      "attestationCount": 247,
      "manifestAdherence": 0.92
    },
    "weights": {
      "successRate": 40,
      "chainCoverage": 25,
      "volume": 20,
      "manifestAdherence": 15
    },
    "proofHash": "f3e1319eec1e7254402684faebb00b62132f0e7ebaa7573f0d13ad6caa0d998b",
    "formulaVersion": "1.0.0",
    "hashAlgorithm": "sha256"
  },
  "trustChain": {
    "merkleRoot": "<sha256 hex>",
    "attestationCount": 247,
    "chainLength": 245
  },
  "capabilities": [
    { "category": "data", "actions": ["data_query"], "invokeCount": 180 },
    { "category": "defi", "actions": ["swap", "transfer"], "invokeCount": 67 }
  ],
  "issuance": {
    "issuer": "did:web:api.claw-net.org",
    "issuedAt": "2026-03-21T14:00:00Z",
    "expiresAt": "2026-06-19T14:00:00Z",
    "platformVersion": "3.0.0"
  },
  "proof": {
    "platformCountersignature": {
      "type": "Ed25519Signature2020",
      "cryptosuite": "eddsa-jcs-2022",
      "proofValue": "<base64url signature>"
    }
  }
}
```

**Note:** `trustScore.score` contains the **base score** (Section 4.1) — deterministic from attestation inputs alone. The proof hash covers this base score. Consumers MAY apply the verification multiplier (Section 4.1.1) at read time. For example, with one verified linked identity (Partial, 1.1×): `min(100, round(79 × 1.1)) = 87`.

**Field requirements:**

| Field | Required | Notes |
|-------|----------|-------|
| `id` | MUST | `did:key` of the agent |
| `version` | MUST | Spec version (`1.0.0`) |
| `signatureAlgorithm` | MUST | Algorithm for identity signatures |
| `algorithmVersion` | MUST | Algorithm version for migration tracking |
| `hashAlgorithm` | MUST | Hash algorithm for trust-layer hashing |
| `agent` | MUST | Agent metadata |
| `publicKey` | MUST | Verification key material |
| `trustScore` | MUST | Base trust score with proof hash |
| `trustChain` | MUST | Merkle-anchored attestation chain summary |
| `capabilities` | SHOULD | Derived from attestation history, not self-declared |
| `issuance` | MUST | Issuer, timestamp, expiry |
| `proof` | MUST | Platform countersignature |

**DID method note:** Agent identifiers use `did:key` (self-certifying, offline-verifiable). Platform issuers use `did:web` (resolvable, DNS-bound).

### 3.3 Crypto-Agility

AID is algorithm-agile by design. The current reference implementation uses Ed25519 for signatures and SHA-256 for trust-layer hashing.

**Requirements for implementers:**
- All AID documents MUST include `signatureAlgorithm`, `algorithmVersion`, and `hashAlgorithm` fields.
- Verifiers MUST read these fields and dispatch to the correct verification algorithm.
- Implementations MUST NOT hardcode `Ed25519` or `sha256` — always read from the document.

**Migration timeline (per NIST IR 8547):**
- **Now:** Ed25519 + SHA-256
- **2027+:** Hybrid Ed25519 + ML-DSA (dual signatures, backwards compatible)
- **2030:** ML-DSA primary (Ed25519 deprecated by NIST)

### 3.4 Key Rotation

Agent keys can be rotated without changing the agent's DID or losing trust history.

**Rotation flow:**
1. Agent (or guardian) sends rotation request signed by the current active key.
2. Server generates a new Ed25519 keypair.
3. The old key is marked `rotated` with a `rotated_at` timestamp. It is NOT deleted.
4. The new key becomes active for all future signatures.
5. The agent's DID does NOT change — the DID is permanent, keys are mutable.

**Verifying old receipts after rotation:**
- Old receipts reference the DID, not the key directly.
- Verifiers look up which key was active at the receipt's `timestamp`.
- Key rotation MUST NOT invalidate existing receipts.

**Guardian key (OPTIONAL):**
- At registration, an agent MAY specify a `guardianAddress` — an external key authorized to freeze the AID and initiate key rotation.

### 3.5 Zero-Friction Onboarding (X-AID-NEW)

Agents can provision identity in a single HTTP call using the `X-AID-NEW` header:

```
POST /aid/skills/sol-price
X-AID-NEW: my-trading-bot
Content-Type: application/json

{"token": "SOL"}
```

**Behavior:**
1. Server creates Ed25519 keypair and AID.
2. Server returns: result + AID document + `privateKeySeed` (returned ONCE, never stored server-side).
3. Future requests use `X-AID-DID` + `X-AID-PROOF` with the provisioned key.

**Rate limits:**
- 3 AIDs per IP per 24 hours.
- 1 AID per unique agent name per 24 hours.
- AIDs that never transact are pruned after 30 days.

**Security:** New AIDs start at trust score 0. They cannot submit feedback (weight = 0) and receive no trust-gated discounts. `X-AID-NEW` provisions an IDENTITY, not free execution.

---

## 4. Trust Scoring

### 4.1 Trust Score Formula (v1.0)

The canonical trust scoring formula uses 4 behavioral dimensions to produce a **base score**:

```
volume    = min(attestationCount / 1000, 1)
rawScore  = successRate × 40 + chainCoverage × 25 + volume × 20 + manifestAdherence × 15
baseScore = max(0, min(100, round(rawScore)))
```

| Dimension | Weight | Range | Source |
|-----------|--------|-------|--------|
| `successRate` | 40% | 0-1 | `success_count / total_attestations` |
| `chainCoverage` | 25% | 0-1 | Fraction of attestations with valid hash-chain links |
| `volume` | 20% | 0-1 | `min(attestationCount / 1000, 1)` |
| `manifestAdherence` | 15% | 0-1 | `manifest_aligned / (aligned + unaligned)`, defaults to 0.5 if no manifests |

**Dimension defaults:** If a dimension has no data, it defaults to 0.5 (neutral) rather than 0.

The base score is deterministic — given identical inputs, every conformant implementation MUST produce the same base score. The proof hash (Section 4.3) covers the base score. AID documents (Section 3.2) contain the base score.

#### 4.1.1 Verification Adjustment (Application Layer)

Implementations MAY apply a verification multiplier for display and verdict determination:

```
adjustedScore = min(100, round(baseScore × verificationMultiplier))
```

| Level | Multiplier | Criteria |
|-------|------------|----------|
| None | 1.0 | No external verification |
| Partial | 1.1 | One verified linked identity |
| Full | 1.2 | Two or more verified linked identities |

The verification multiplier is an application-layer adjustment. It MUST NOT be included in the proof hash computation (Section 4.3). Verification status is dynamic — agents link and unlink external identities over time. Including dynamic state in the proof hash would break the determinism guarantee: same attestation inputs must always produce the same proof hash.

The adjusted score is used for verdict determination (Section 4.4). The base score is used for proof verification and cross-implementation comparison.

#### 4.1.2 Deterministic Computation Algorithm

Implementations MUST use IEEE 754 binary64 (double-precision floating-point) for all trust score arithmetic. The computation is specified as a numbered algorithm. Every conformant implementation MUST produce identical intermediate values at every step for the same inputs.

**Algorithm:**

Given inputs `successRate` (0-1), `chainCoverage` (0-1), `attestationCount` (non-negative integer), `manifestAdherence` (0-1), and default weights `W = {successRate: 40, chainCoverage: 25, volume: 20, manifestAdherence: 15}`:

1. **Normalize volume:** `volume = min(attestationCount / 1000.0, 1.0)`
2. **Apply manifest default:** If `attestationCount == 0` AND `manifestAdherence == 0`, set `manifestAdherence = 0.5`. Otherwise, keep the original value.
3. **Compute dimension products** (each multiplication is independent):
   - `d1 = successRate × W.successRate`
   - `d2 = chainCoverage × W.chainCoverage`
   - `d3 = volume × W.volume`
   - `d4 = manifestAdherence × W.manifestAdherence`
4. **Sum left-to-right:** `rawScore = ((d1 + d2) + d3) + d4`
   Parentheses indicate REQUIRED evaluation order. Do NOT reorder or use fused operations.
5. **Round to integer (half-up):** `baseScore = floor(rawScore + 0.5)`
   This is "round half up" — if the fractional part is exactly 0.5, round toward positive infinity.
6. **Clamp:** `baseScore = max(0, min(100, baseScore))`

**Rounding mode is critical.** At score boundaries (e.g., rawScore = 89.5), the rounding mode determines whether an agent is `trusted` (89) or `proceed`-eligible (90). A single bit of divergence between implementations breaks the determinism guarantee.

**Cross-language implementation:**

| Language | `roundHalfUp(x)` for x ≥ 0 | Caution |
|----------|---------------------------|---------|
| JavaScript | `Math.round(x)` | Correct for non-negative values |
| Python | `math.floor(x + 0.5)` | Do NOT use `round(x)` — Python uses banker's rounding (round-half-to-even) |
| Rust | `(x + 0.5).floor() as i32` | Do NOT use `.round()` — Rust rounds half away from zero (same result for positive, differs for negative) |
| Go | `int(math.Floor(x + 0.5))` | Do NOT use `math.Round(x)` — Go rounds half away from zero |

**Worked example (ts-001):**

```
Inputs: successRate=0.95, chainCoverage=0.88, attestationCount=247, manifestAdherence=0.92

Step 1: volume = min(247 / 1000, 1) = 0.247
Step 2: attestationCount > 0, so manifestAdherence stays 0.92
Step 3: d1 = 0.95 × 40 = 38.0
        d2 = 0.88 × 25 = 22.0
        d3 = 0.247 × 20 = 4.9399999999999995  ← exact IEEE 754 binary64 value
        d4 = 0.92 × 15 = 13.8
Step 4: rawScore = ((38.0 + 22.0) + 4.9399999999999995) + 13.8 = 78.74
Step 5: baseScore = floor(78.74 + 0.5) = floor(79.24) = 79
Step 6: clamp(79) = 79  ✓
```

Note: `0.247 × 20` produces `4.9399999999999995`, not `4.94`. These are different IEEE 754 doubles. Test vectors include the exact intermediate values so cross-language divergence is pinpointed to the exact step.

Full intermediate test vectors are published in `test-vectors/trust-score.json`.

### 4.2 Trust Input Hierarchy (Abstract)

AID-Trust defines input classes abstractly. AID-Receipt maps concrete constructs to these classes (see `protocols/composability.md`).

| Input Class | Weight | Description |
|-------------|--------|-------------|
| Bilateral verified interactions | 1.0 | Both parties sign and agree on outcome |
| Bilateral disputed interactions | 0.3 | Both parties sign but disagree |
| Unilateral attested interactions | 0.5 | Platform attestations with evidence |
| External oracle data | 0.3 | ERC-8004, third-party scores |
| Self-declared inputs | 0.1 | Manifest claims, capability declarations |

### 4.3 Proof Hash

Every trust score MUST include a cryptographic proof hash covering the **base score** (Section 4.1):

```
proofHash = SHA-256(JCS({inputs, weights, score}))
```

Where `score` is the base score (NOT the verification-adjusted score from Section 4.1.1), and JCS is JSON Canonicalization Scheme (RFC 8785). Given identical attestation inputs, every implementation MUST produce identical proof hashes regardless of the agent's current verification status.

### 4.4 Trust Verdicts

AID-Trust defines the score-to-verdict mapping. Verdicts use the **adjusted score** (Section 4.1.1) — the base score with verification multiplier applied:

| Adjusted Score Range | Verdict |
|----------------------|---------|
| 0-19 | `new` |
| 20-39 | `building` |
| 40-59 | `caution` |
| 60-79 | `standard` |
| 80-89 | `trusted` |
| 90+ (with additional gates) | `proceed` |

**`proceed` tier requirements (all must be met):**
- Adjusted score 90 or above
- Verification multiplier at "Partial" (1.1) or higher
- Agent active for at least 6 months (from first attestation)
- Agent has generated at least $50 cumulative platform revenue

**`avoid` flag:** A separate manual flag applied by validators or structured reports (spam, fraud, copyright). Not score-based — an agent can be score 70 and flagged `avoid`. Removal requires admin review or validator consensus (3 validators agree). For settlement effects of the avoid flag, see AID-Settle.

**Tier boundary resolution:** The adjusted score is a float (e.g., 78.25). Tier boundaries use floor: 78.25 maps to `standard` (60-79).

Settlement modes and pricing discounts per verdict are defined by AID-Settle, not AID-Trust.

### 4.5 Attestation Record Format

Every transaction produces a signed attestation:

```json
{
  "attestationId": "att-a1b2c3d4",
  "sequenceNumber": 248,
  "agentDid": "did:key:zABC...",
  "actionType": "skill_invoke",
  "outcomeStatus": "success",
  "inputHash": "<sha256 hex of request>",
  "responseHash": "<sha256 hex of response>",
  "sourceHashes": [
    { "source": "coingecko-price", "hash": "<sha256>", "fetchedAt": "2026-03-21T14:30:00Z" }
  ],
  "executionProof": {
    "totalSteps": 3,
    "successfulSteps": 3,
    "cachedSteps": 1,
    "totalLatencyMs": 230,
    "stepEndpoints": ["coingecko-price", "birdeye-price", "jupiter-price"],
    "proofHash": "<sha256 hex>"
  },
  "manifestAdherence": {
    "aligned": true,
    "confidence": 0.95
  },
  "prevAttestationHash": "<sha256 hex of previous attestation>",
  "creditsCharged": 1.5,
  "durationMs": 230,
  "signature": "<HMAC-SHA256 with platform signing key>",
  "hashAlgorithm": "sha256",
  "createdAt": "2026-03-21T14:30:02Z"
}
```

**Properties:**
- **Hash-chained:** `prevAttestationHash` links each attestation to its predecessor, creating a tamper-evident chain.
- **Sequence-numbered:** `sequenceNumber` provides replay protection and gap detection.
- **Content-addressed:** `inputHash` and `responseHash` prove what was processed without revealing data.

See the [AID Attestation Profile](../../spec/profiles/aid-attestation-profile.md) for the full interoperability specification.

### 4.6 Trust Decay

Trust scores lose weight over time for inactive agents:

- **Rate:** 10% weight loss per 30 days of inactivity (no new attestations).
- **Floor:** Minimum decay factor of 0.1 (scores never fully zero from decay alone).
- **Resumption:** Decay halts immediately when a new attestation is recorded.

Implementers MAY use adaptive decay rates per category (e.g., faster decay for high-frequency categories).

### 4.7 Merkle Snapshots

Trust data is Merkle-anchored for offline verification.

**Snapshot process (every 4 hours, +/-15 min random jitter):**
1. Cron captures a cutoff timestamp BEFORE starting tree computation.
2. Build Merkle tree from all attestations with `created_at <= cutoff`.
3. Attestations arriving AFTER cutoff go into the NEXT snapshot.
4. Anchor Merkle root on-chain (Base L2, ~$0.001/tx).

**Merkle proof format:**

```json
[
  { "position": "left",  "hash": "sha256:aabb..." },
  { "position": "right", "hash": "sha256:ccdd..." },
  { "position": "left",  "hash": "sha256:eeff..." }
]
```

**Verification algorithm:**
1. Start with `currentHash = SHA-256(receiptId + timestamp + payerDid + providerDid)`.
2. For each proof element:
   - If `position` is `"left"`: `currentHash = SHA-256(element.hash + currentHash)`
   - If `position` is `"right"`: `currentHash = SHA-256(currentHash + element.hash)`
3. Final `currentHash` MUST equal the published `merkleRoot`.

Proof size is O(log n) — 20 hashes for 1M agents (640 bytes).

---

## 5. HTTP Headers

### 5.1 Request Headers (Client → Server)

| Header | Required | Description |
|--------|----------|-------------|
| `X-AID-DID` | REQUIRED | Agent's DID (`did:key:z6Mk...`) |
| `X-AID-PROOF` | REQUIRED | Ed25519 signature over canonical signing input (Section 5.3) |
| `X-AID-TIMESTAMP` | REQUIRED | ISO 8601 UTC with Z suffix (e.g., `2026-03-21T14:30:00Z`) |
| `X-AID-NONCE` | REQUIRED | 16 random bytes, hex-encoded (32 chars) for anti-replay |
| `X-AID-TRUST-SCORE` | OPTIONAL | Claimed score (hint only — server MUST NOT use for authorization) |
| `X-AID-VERSION` | OPTIONAL | Protocol version (default: `1.0`). If unsupported, server returns 406. |

### 5.2 Response Headers (Server → Client)

| Header | Required | Description |
|--------|----------|-------------|
| `X-AID-PROVIDER-DID` | REQUIRED | Server's DID for mutual authentication |
| `X-AID-PROVIDER-PROOF` | REQUIRED | Server's Ed25519 countersignature (Section 5.4) |
| `X-AID-TRUST-VERIFIED` | RECOMMENDED | Server's independently verified trust score for the caller |

Additional response headers (`X-AID-RECEIPT`, `X-AID-FEEDBACK-URL`) are defined by AID-Receipt.

### 5.2.1 ABNF Grammar (RFC 5234)

Formal syntax for all AID-Trust HTTP headers. Core rules (`ALPHA`, `DIGIT`, `HEXDIG`, `SP`) are from [RFC 5234 Appendix B](https://www.rfc-editor.org/rfc/rfc5234#appendix-B).

```abnf
; ── Request Headers ──────────────────────────────────────────────

X-AID-DID           = "did:key:z" 1*base58btc-char
                       ; W3C did:key with Ed25519 multicodec (0xed01)
                       ; Example: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK

X-AID-PROOF         = 1*base64url-char
                       ; Ed25519 signature over canonical signing input (Section 5.3)
                       ; base64url encoding without padding (RFC 4648 §5)

X-AID-TIMESTAMP     = date-time-z
                       ; ISO 8601 UTC with mandatory Z suffix
                       ; Server MUST reject timezone offsets (+/-HH:MM)

X-AID-NONCE         = 32HEXDIG
                       ; 16 cryptographically random bytes, lowercase hex-encoded
                       ; Server tracks seen nonces for 300-second replay window

X-AID-TRUST-SCORE   = 1*3DIGIT
                       ; Optional, 0-100. Hint only — server MUST NOT use for authz

X-AID-VERSION       = 1*DIGIT "." 1*DIGIT
                       ; Protocol version (default "1.0")
                       ; Server returns 406 if unsupported

; ── Response Headers ─────────────────────────────────────────────

X-AID-PROVIDER-DID   = "did:key:z" 1*base58btc-char
                        ; Server's DID for mutual authentication

X-AID-PROVIDER-PROOF = 1*base64url-char
                        ; Server's Ed25519 countersignature (Section 5.4)

X-AID-TRUST-VERIFIED = 1*3DIGIT
                        ; Server's independently verified score for the caller

; ── Onboarding Header ───────────────────────────────────────────

X-AID-NEW            = 1*63(ALPHA / DIGIT / "-" / "_")
                        ; Agent display name for zero-friction provisioning (Section 3.5)
                        ; Max 63 chars, alphanumeric + hyphen + underscore

; ── Shared Rules ─────────────────────────────────────────────────

date-time-z      = 4DIGIT "-" 2DIGIT "-" 2DIGIT "T"
                   2DIGIT ":" 2DIGIT ":" 2DIGIT "Z"
                   ; e.g., 2026-03-21T14:30:00Z
                   ; Fractional seconds MAY be present but are not required

base58btc-char   = %x31-39 / %x41-48 / %x4A-4E / %x50-5A
                 / %x61-6B / %x6D-7A
                   ; Bitcoin base58: 1-9 A-H J-N P-Z a-k m-z
                   ; Excludes 0, O, I, l (ambiguous characters)

base64url-char   = ALPHA / DIGIT / "-" / "_"
                   ; RFC 4648 §5, no padding
```

### 5.2.2 JSON Schema

Schemas for the three core AID-Trust data structures. Implementations SHOULD use these for validation.

**TrustScoreResult** — output of `computeTrustScore()` (Section 4.1):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "TrustScoreResult",
  "type": "object",
  "required": ["score", "inputs", "weights", "proofHash", "formulaVersion", "hashAlgorithm"],
  "properties": {
    "score": { "type": "integer", "minimum": 0, "maximum": 100, "description": "Base score (Section 4.1)" },
    "inputs": {
      "type": "object",
      "required": ["successRate", "chainCoverage", "attestationCount", "manifestAdherence"],
      "properties": {
        "successRate": { "type": "number", "minimum": 0, "maximum": 1 },
        "chainCoverage": { "type": "number", "minimum": 0, "maximum": 1 },
        "attestationCount": { "type": "integer", "minimum": 0 },
        "manifestAdherence": { "type": "number", "minimum": 0, "maximum": 1 }
      }
    },
    "weights": {
      "type": "object",
      "required": ["successRate", "chainCoverage", "volume", "manifestAdherence"],
      "properties": {
        "successRate": { "type": "integer" },
        "chainCoverage": { "type": "integer" },
        "volume": { "type": "integer" },
        "manifestAdherence": { "type": "integer" }
      }
    },
    "proofHash": { "type": "string", "pattern": "^[a-f0-9]{64}$", "description": "SHA-256 of JCS({inputs, weights, score})" },
    "formulaVersion": { "type": "string", "pattern": "^\\d+\\.\\d+\\.\\d+$" },
    "hashAlgorithm": { "type": "string", "enum": ["sha256"] }
  }
}
```

**HeartbeatResponse** — `GET /aid/heartbeat` (Section 6):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "HeartbeatResponse",
  "type": "object",
  "required": ["protocolVersion", "provider", "services", "cryptoAgility", "platformKey", "timestamp", "extensions"],
  "properties": {
    "protocolVersion": { "type": "string", "pattern": "^\\d+\\.\\d+\\.\\d+$" },
    "provider": {
      "type": "object",
      "required": ["did", "trustScore"],
      "properties": {
        "did": { "type": "string", "pattern": "^did:key:z" },
        "trustScore": { "type": "integer", "minimum": 0, "maximum": 100 },
        "uptime": { "type": "number", "minimum": 0, "maximum": 1 },
        "verified": { "type": "boolean" }
      }
    },
    "services": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "type", "status"],
        "properties": {
          "id": { "type": "string" },
          "type": { "type": "string" },
          "price": { "type": "string" },
          "trustGate": { "type": "integer", "minimum": 0, "maximum": 100 },
          "status": { "type": "string", "enum": ["healthy", "degraded", "offline"] }
        }
      }
    },
    "cryptoAgility": {
      "type": "object",
      "required": ["current", "supported", "hashAlgorithm"],
      "properties": {
        "current": { "type": "string" },
        "supported": { "type": "array", "items": { "type": "string" } },
        "planned": { "type": "array", "items": { "type": "string" } },
        "hashAlgorithm": { "type": "string" },
        "pqcReady": { "type": "boolean" }
      }
    },
    "platformKey": { "type": "string", "description": "base64url Ed25519 public key" },
    "timestamp": { "type": "string", "format": "date-time" },
    "extensions": { "type": "object", "description": "Extended by AID-Receipt and AID-Settle" }
  }
}
```

**TrustVerdict** — score-to-verdict mapping (Section 4.4):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "TrustVerdict",
  "type": "object",
  "required": ["verdict"],
  "properties": {
    "verdict": { "type": "string", "enum": ["new", "building", "caution", "standard", "trusted", "proceed"] }
  }
}
```

### 5.3 Client Signing (X-AID-PROOF)

The canonical signing input binds the signature to the DID, timestamp, nonce, HTTP method, path, and request body:

```
signatureInput = SHA-256(
  did + "\n" +
  timestamp + "\n" +
  nonce + "\n" +
  method + " " + path + "\n" +
  SHA-256(requestBody)
)

X-AID-PROOF = base64url(Ed25519Sign(privateKey, signatureInput))
```

**Encoding requirements:**
- Timestamps MUST be UTC with Z suffix. Timezone offsets MUST be rejected.
- The inner `SHA-256(requestBody)` is encoded as lowercase hex (64 chars) in the signing string.
- Nonce MUST be 16 cryptographically random bytes, hex-encoded (32 chars).
- Server MUST reject proofs where `|now - timestamp| > 300` seconds (5-minute window).
- Server MUST track seen nonces for 5-minute window. Duplicate nonce returns 409.
- Server clock SHOULD be NTP-synchronized.

### 5.4 Server Signing (X-AID-PROVIDER-PROOF)

The server countersigns every response for mutual authentication:

```
providerSignatureInput = SHA-256(
  providerDid + "\n" +
  receiptId + "\n" +
  timestamp + "\n" +
  SHA-256(responseBody)
)

X-AID-PROVIDER-PROOF = base64url(Ed25519Sign(serverPrivateKey, providerSignatureInput))
```

The client can verify this offline using the server's public key.

---

## 6. Heartbeat Protocol

### 6.1 Specification

Every AID-Trust conformant server MUST expose `GET /aid/heartbeat`:

```json
{
  "protocolVersion": "1.0.0",
  "provider": {
    "did": "did:key:zXYZ...",
    "trustScore": 94,
    "uptime": 0.998,
    "verified": true
  },
  "services": [
    {
      "id": "sol-price",
      "type": "data_query",
      "price": "0.001",
      "trustGate": 0,
      "status": "healthy"
    }
  ],
  "cryptoAgility": {
    "current": "Ed25519",
    "supported": ["Ed25519"],
    "planned": ["ML-DSA-44"],
    "hashAlgorithm": "sha256",
    "pqcReady": false
  },
  "platformKey": "<base64url Ed25519 public key>",
  "timestamp": "2026-03-21T14:30:00Z",
  "extensions": {}
}
```

**Required fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `protocolVersion` | MUST | AID protocol version |
| `provider.did` | MUST | Server's DID |
| `provider.trustScore` | MUST | Server's own trust score |
| `services` | MUST | Available services |
| `cryptoAgility` | MUST | Supported signature algorithms |
| `platformKey` | MUST | Platform's Ed25519 public key |
| `timestamp` | MUST | Server's current time |
| `extensions` | MUST | Empty object (extended by AID-Receipt and AID-Settle) |

AID-Receipt adds receipt format info to `extensions.aidReceipt`. AID-Settle adds pricing tiers to `extensions.aidSettle`. Implementations MUST ignore unknown extension keys.

### 6.2 Well-Known Discovery

AID-conformant servers SHOULD serve `/.well-known/aid.json`:

```json
{
  "did": "did:web:api.example.com",
  "trustEndpoint": "/v1/aid/:did/trust",
  "verifyEndpoint": "/v1/aid/verify",
  "supportedSigningAlgorithms": ["Ed25519"],
  "supportedHashAlgorithms": ["SHA-256"],
  "specVersion": "1.0.0",
  "trustVectorSupported": true,
  "spec": "https://github.com/aidprotocol/aid-spec"
}
```

### 6.3 Authenticated Heartbeat

If the client includes `X-AID-DID` + `X-AID-PROOF`, the response additionally includes personalized data:

```json
{
  "consumer": {
    "trustScore": 87,
    "verified": true,
    "pricingTier": { "verdict": "proceed" },
    "recentReceipts": 47,
    "feedbackPending": 3,
    "alerts": [
      { "type": "trust_degradation", "provider": "did:key:zDEF...", "delta": -12 }
    ]
  }
}
```

---

## 7. Privacy Model

### 7.1 Public Data (No Authentication Required)

| Data | Access |
|------|--------|
| DID exists (yes/no) | Public |
| Trust verdict (5 levels) | Public |
| Verification tier | Public |
| Capability categories (no counts) | Public |
| Active since (date) | Public |

### 7.2 Owner-Only Data (Requires X-AID-PROOF from DID Owner)

| Data | Access |
|------|--------|
| Exact trust score (0-100) | Owner only |
| Full capability breakdown with invoke counts | Owner only |
| Complete attestation history | Owner only |
| Detailed feedback received | Owner only |

### 7.3 Provider View (During Transaction)

During a transaction, the server sees: exact trust score (for pricing), relevant capabilities, recent feedback summary (last 30 days). Servers MUST NOT store or redistribute the exact trust score beyond what is needed for the transaction.

### 7.4 Right to Erasure (GDPR)

AID implementations MUST support identity erasure via `DELETE /v1/aid/:did`:

1. Delete all off-chain data (keys, snapshots, attestations, capabilities).
2. Insert tombstone record (DID + erasure timestamp) to prevent re-creation.
3. On-chain Merkle roots remain as orphaned hashes (CNIL-compatible approach).
4. Return 204 No Content.

---

## 8. Security

### 8.1 Required Properties

1. **HTTPS REQUIRED** — all AID endpoints MUST be served over TLS.
2. **TIMESTAMP VALIDATION** — signatures include current timestamp. Server rejects `|now - timestamp| > 300s`.
3. **BODY BINDING** — Ed25519 signature covers SHA-256 of request body.
4. **NONCE TRACKING** — 16-byte random nonces tracked for 5-minute window. Duplicates rejected (409).
5. **KEY ROTATION** — compromised keys can be rotated without losing identity.
6. **RATE LIMITING** — public endpoints SHOULD be rate-limited by IP.
7. **AUDIT TRAIL** — all AID operations produce signed attestations.
8. **FAIL-CLOSED** — middleware MUST default to rejecting requests when trust cannot be verified.
9. **MUTUAL AUTHENTICATION** — both client and server prove identity via Ed25519 signatures.

### 8.2 Error Responses

| Status | Code | Condition |
|--------|------|-----------|
| 401 | `AID_SIGNATURE_INVALID` | `X-AID-PROOF` verification failed |
| 403 | `AID_TRUST_GATE_BLOCKED` | Trust score below minimum |
| 406 | `AID_VERSION_UNSUPPORTED` | `X-AID-VERSION` not supported |
| 409 | `AID_NONCE_REPLAY` | Nonce already seen within window |
| 428 | `AID_PROOF_MISSING` | `X-AID-DID` present but `X-AID-PROOF` missing |

Error response body:
```json
{
  "error": "Trust score too low",
  "code": "AID_TRUST_GATE_BLOCKED",
  "callerScore": 35,
  "requiredScore": 40,
  "verdict": "building"
}
```

Additional error codes (`AID_PAYMENT_REQUIRED`, `AID_SETTLEMENT_FAILED`, etc.) are defined by AID-Settle.

### 8.3 Ed25519 Implementation Requirements

**8.3.1** Implementations MUST use Ed25519 libraries that derive the public key internally from the private key. Libraries accepting a separate public key parameter are vulnerable to the Double Public Key Oracle Attack and MUST NOT be used. See [MystenLabs/ed25519-unsafe-libs](https://github.com/MystenLabs/ed25519-unsafe-libs).

**8.3.2** Implementations MUST NOT use CLI tools (e.g., `openssl dgst`) for Ed25519 operations. CVE-2025-15469 demonstrated silent truncation. All operations MUST use library-level APIs.

**8.3.3** Implementations using libsodium MUST use version 1.0.20+ (CVE-2025-69277).

**8.3.4** Implementations MUST maintain an `allowedAlgorithms` whitelist. Documents claiming unlisted algorithms MUST be rejected. Default: `["EdDSA"]`.

**8.3.5** Recommended libraries:
- **JavaScript/TypeScript:** Node.js built-in `crypto` module, or `@noble/ed25519`
- **Rust:** `ring` or `ed25519-dalek`
- **C:** libsodium 1.0.20+

### 8.4 Relationship to RFC 9421 (HTTP Message Signatures)

[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) defines a general-purpose framework for signing HTTP messages using component identifiers. AID-Trust uses a purpose-built signing scheme (Section 5.3) instead of adopting RFC 9421 directly.

**Why AID-Trust does not use RFC 9421:**

1. **DID binding.** AID signing binds the signature to the agent's `did:key` identifier as the first element of the signing input. RFC 9421 has no native DID concept — expressing this would require a custom derived component, adding complexity without interoperability benefit.
2. **Body commitment.** AID computes `SHA-256(requestBody)` and includes it in the signing string. RFC 9421 uses `Content-Digest` (RFC 9530) for body coverage, which requires an additional header and a separate hash computation.
3. **Mutual authentication.** AID requires both client and server to sign (Sections 5.3 and 5.4). RFC 9421 is designed for request signing; response signing requires a separate `Signature` header with different parameters, doubling the header complexity.
4. **Simplicity.** AID's signing input is 5 concatenated fields → SHA-256 → Ed25519 sign. RFC 9421 requires signature base construction with structured fields, component identifiers, and signature parameters. For agent-to-agent communication where both sides run AID middleware, the simpler scheme reduces implementation surface.

**How AID-Trust maps to RFC 9421 concepts:**

| RFC 9421 Concept | AID-Trust Equivalent |
|------------------|---------------------|
| `keyid` parameter | `X-AID-DID` header |
| `created` parameter | `X-AID-TIMESTAMP` header |
| `nonce` parameter | `X-AID-NONCE` header |
| `@method` component | Included in signing string (line 4) |
| `@target-uri` component | Path included in signing string (line 4) |
| `content-digest` component | `SHA-256(requestBody)` in signing string (line 5) |
| `alg` parameter | `signatureAlgorithm` in AID document |

**Migration path:** If the ecosystem converges on RFC 9421 for agent authentication, AID could define an RFC 9421 profile that maps AID headers to structured field components. The cryptographic operations (Ed25519 + SHA-256) are identical — only the framing differs. This would be a non-breaking additive change (support both, prefer 9421 when negotiated via `X-AID-VERSION`).

---

## 9. Governance

### 9.1 Formula Versioning

The trust scoring formula is versioned. All middleware MUST pin to a specific formula version:

```typescript
server.use(aidTrust({ formulaVersion: '1.0.0' }));
```

- **Patch (1.0.x):** Bug fixes, no output changes.
- **Minor (1.x.0):** New optional dimensions, existing scores unchanged.
- **Major (x.0.0):** Weight changes, dimension removal, score output changes.

Major version changes MUST be announced 30 days before activation. Middleware MUST NOT silently adopt new major versions.

### 9.2 Governance Model

- **Phase 1-2 (current):** Benevolent maintainer + advisory board. Changes published 30 days before activation.
- **Phase 3+:** Community governance with public comment periods.

### 9.3 Protocol Versioning

- **Minor (1.0 → 1.1):** Additive only, no breaking changes.
- **Major (1.x → 2.x):** Breaking changes. Old endpoints maintained for 6 months.
- Unsupported `X-AID-VERSION` returns 406 with supported versions list.

---

## 10. Conformance Levels

### Level 1 — AID Core Conformant

MUST implement:
- Identity headers (`X-AID-DID`, `X-AID-PROOF`, `X-AID-TIMESTAMP`, `X-AID-NONCE`)
- Signature verification (canonical signing input, Section 5.3)
- Heartbeat endpoint (`GET /aid/heartbeat`)
- Error semantics (Section 8.2)

CAN verify trust but does NOT compute it. Example: `@aidprotocol/mcp-trust` middleware.

### Level 2 — AID Trust Conformant

MUST implement Level 1, PLUS:
- Trust scoring using canonical formula (Section 4.1)
- Trust verdicts (Section 4.4)
- Proof hash (Section 4.3)
- Trust decay (Section 4.6)
- Merkle snapshots (Section 4.7)

CAN serve as a trust oracle for Level 1 implementations. Example: independent trust oracle operator.

---

## Appendix A: Test Vectors

### A.1 DID Resolution

**Input:** `did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`

**Steps:**
1. Strip prefix → `z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`
2. Decode base58btc (multibase `z` prefix) to 34 raw bytes.
3. Verify first 2 bytes are `0xed 0x01`.
4. Remaining 32 bytes are the raw Ed25519 public key.

### A.2 Signing Input Construction

**Given:**
- DID: `did:key:z6MkTest1234`
- Timestamp: `2026-03-21T14:30:00Z`
- Nonce: `a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8`
- Method: `POST`
- Path: `/aid/skills/sol-price`
- Body: `{"token":"SOL"}`

**Steps:**
1. `SHA-256('{"token":"SOL"}')` → 64-char lowercase hex
2. Construct signing string (fields joined by `\n`)
3. `signatureInput = SHA-256(signingString)`
4. `proof = base64url(Ed25519Sign(privateKey, signatureInput))`

### A.3 Trust Score Proof Hash

**Given:**
```json
{
  "inputs": { "successRate": 0.95, "chainCoverage": 0.88, "attestationCount": 247, "manifestAdherence": 0.92 },
  "weights": { "successRate": 40, "chainCoverage": 25, "volume": 20, "manifestAdherence": 15 },
  "score": 79
}
```

1. Apply JCS (RFC 8785) canonicalization.
2. `proofHash = SHA-256(canonicalized_json)` → `f3e1319eec1e7254402684faebb00b62132f0e7ebaa7573f0d13ad6caa0d998b`

Any implementation MUST produce the same `proofHash` for the same inputs. See `test-vectors/trust-score.json` for the full deterministic computation (Section 4.1.2).

### A.4 Merkle Proof Verification

**Given:**
- Leaf: `SHA-256("rcpt-abc123" + "2026-03-21T14:30:00Z" + "did:key:zA" + "did:key:zB")`
- Proof: `[{"position":"left","hash":"sha256:aa..."},{"position":"right","hash":"sha256:bb..."}]`
- Expected root: `sha256:cc...`

**Steps:**
1. `h = leaf_hash`
2. `h = SHA-256(proof[0].hash + h)` (left sibling goes first)
3. `h = SHA-256(h + proof[1].hash)` (right sibling goes second)
4. Assert `h == expected_root`

---

## Appendix B: RATS Architecture Mapping (RFC 9334)

AID-Trust's trust scoring pipeline maps to the IETF Remote ATtestation procedureS (RATS) architecture ([RFC 9334](https://www.rfc-editor.org/rfc/rfc9334)). This appendix uses RATS terminology to help DIF and IETF reviewers situate AID-Trust within established frameworks.

### B.1 Role Mapping

| RATS Role | AID-Trust Equivalent | Description |
|-----------|---------------------|-------------|
| **Attester** | Agent (did:key holder) | Produces claims about its behavior via signed attestations |
| **Verifier** | Trust oracle (Level 2 conformant, Section 10) | Appraises attestation evidence, computes trust scores |
| **Relying Party** | Service consumer (Level 1 conformant) | Uses trust verdicts for access/pricing decisions |
| **Endorser** | Cross-platform attestation source | Third-party claims (ERC-8004, external oracles) that strengthen trust signals |

### B.2 Data Flow Mapping

| RATS Concept | AID-Trust Equivalent | Section |
|-------------|---------------------|---------|
| **Evidence** | Signed attestation record | 4.5 |
| **Attestation Result** | Trust score + proof hash + verdict | 4.1, 4.3, 4.4 |
| **Reference Values** | Merkle-anchored trust snapshots | 4.7 |
| **Endorsement** | Cross-platform attestation (weight 0.3) | 4.2 |
| **Appraisal Policy** | Trust scoring formula (v1.0, 4 dimensions) | 4.1, 4.1.2 |
| **Evidence freshness** | Timestamp validation (300s window) + nonce replay | 5.3, 8.1 |

### B.3 Architectural Differences

AID-Trust extends the RATS model in two ways:

1. **Behavioral trust, not platform attestation.** RATS focuses on platform integrity (e.g., "is this device running trusted firmware?"). AID-Trust scores *behavioral history* — transaction success rates, attestation chain coverage, manifest adherence. The attester IS the agent's behavior over time, not its hardware.

2. **Offline verification.** RATS typically requires online interaction with a Verifier. AID-Trust's Merkle-anchored snapshots + proof hashes enable fully offline verification — a Relying Party can verify a trust score with pure math (Ed25519 + SHA-256), no network calls to any Verifier.

---

## Appendix C: References

- W3C DID Core v1.1: https://www.w3.org/TR/did-core/
- W3C `did:key` Method: https://w3c-ccg.github.io/did-method-key/
- JSON Canonicalization Scheme (RFC 8785): https://www.rfc-editor.org/rfc/rfc8785
- ABNF Syntax (RFC 5234): https://www.rfc-editor.org/rfc/rfc5234
- RFC 2119 (Key Words): https://www.rfc-editor.org/rfc/rfc2119
- HTTP Message Signatures (RFC 9421): https://www.rfc-editor.org/rfc/rfc9421
- RATS Architecture (RFC 9334): https://www.rfc-editor.org/rfc/rfc9334
- DIF Trusted AI Agents Working Group: https://identity.foundation/working-groups/trusted-agents.html
- NIST FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
- NIST IR 8547 (PQC Migration): https://csrc.nist.gov/pubs/ir/8547/final
- ERC-8004 (Agent Identity): https://eips.ethereum.org/EIPS/eip-8004
- x402 Protocol: https://github.com/coinbase/x402
- AID Trust Scoring Library: https://www.npmjs.com/package/@aidprotocol/trust-compute
- AID MCP Trust Middleware: https://www.npmjs.com/package/@aidprotocol/mcp-trust
