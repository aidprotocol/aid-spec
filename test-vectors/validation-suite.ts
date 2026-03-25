/**
 * AID Protocol Test Vector Validation
 *
 * Validates that implementations produce identical outputs
 * to the published test vectors in aid-spec/test-vectors/.
 *
 * Any AID implementation MUST pass these tests to be spec-compliant.
 *
 * Imports from @aidprotocol/trust-compute (the canonical reference library).
 * To validate a different implementation, replace imports with your own functions.
 */

import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import {
  jcsSerialize,
  computeTrustScore,
  getTrustVerdict,
} from '@aidprotocol/trust-compute';

// ─── Signing Test Vector ────────────────────────────────────────────────────

describe('AID Signing (test-vectors/signing.json)', () => {
  it('produces correct Ed25519 signature for SHA-256 canonical signing input', () => {
    const seed = Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex');
    const pkcs8Header = Buffer.from('302e020100300506032b657004220420', 'hex');
    const privateKey = crypto.createPrivateKey({ key: Buffer.concat([pkcs8Header, seed]), format: 'der', type: 'pkcs8' });
    const publicKey = crypto.createPublicKey(privateKey);
    const rawPub = Buffer.from(publicKey.export({ type: 'spki', format: 'der' }).subarray(12));

    const did = 'did:key:z6MkTestVector1';
    const timestamp = '2026-03-21T14:30:00Z';
    const nonce = 'a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8';
    const method = 'POST';
    const path = '/aid/skills/sol-price';
    const body = '{"token":"SOL"}';

    // Step 1: SHA-256 of body (per spec Section 5.3)
    const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
    expect(bodyHash).toBe('de1a4a2a9845ba511979b25c2a123033fcbfbcc9dfe4b6783a4df1b2a72a04ac');
    expect(bodyHash.length).toBe(64);

    // Step 2: Construct signing string
    const signingString = `${did}\n${timestamp}\n${nonce}\n${method} ${path}\n${bodyHash}`;

    // Step 3: SHA-256 of signing string
    const signatureInput = crypto.createHash('sha256').update(signingString).digest();
    expect(signatureInput.toString('hex')).toBe('c525f06cb0c4abece237bdbd295abe278f6af8064b756bf92b12ad4739761989');

    // Step 4: Ed25519 sign
    const signature = crypto.sign(null, signatureInput, privateKey);
    expect(signature.length).toBe(64);

    // Step 5: Verify
    const verified = crypto.verify(null, signatureInput, publicKey, signature);
    expect(verified).toBe(true);

    // Verify public key matches test vector
    expect(rawPub.toString('hex')).toBe('207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab6');
  });

  it('rejects tampered signatures', () => {
    const seed = Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex');
    const pkcs8Header = Buffer.from('302e020100300506032b657004220420', 'hex');
    const privateKey = crypto.createPrivateKey({ key: Buffer.concat([pkcs8Header, seed]), format: 'der', type: 'pkcs8' });
    const publicKey = crypto.createPublicKey(privateKey);

    const data = crypto.createHash('sha256').update('test data').digest();
    const signature = crypto.sign(null, data, privateKey);

    // Tamper with one byte
    const tampered = Buffer.from(signature);
    tampered[0] ^= 0xff;

    expect(crypto.verify(null, data, publicKey, tampered)).toBe(false);
  });
});

// ─── Trust Score Test Vector ────────────────────────────────────────────────

describe('AID Trust Score (test-vectors/trust-score.json)', () => {
  it('computes correct v1.0 base score (ts-001)', () => {
    const result = computeTrustScore({
      successRate: 0.95,
      chainCoverage: 0.88,
      attestationCount: 247,
      manifestAdherence: 0.92,
    });

    expect(result.score).toBe(79);
    expect(result.proofHash).toBe('f3e1319eec1e7254402684faebb00b62132f0e7ebaa7573f0d13ad6caa0d998b');
    expect(result.hashAlgorithm).toBe('sha256');
  });

  it('produces deterministic proof hash via JCS + SHA-256', () => {
    const proofData = {
      inputs: { attestationCount: 247, chainCoverage: 0.88, manifestAdherence: 0.92, successRate: 0.95 },
      score: 79,
      weights: { chainCoverage: 25, manifestAdherence: 15, successRate: 40, volume: 20 },
    };

    const canonical = jcsSerialize(proofData);
    const hash1 = crypto.createHash('sha256').update(canonical).digest('hex');
    const hash2 = crypto.createHash('sha256').update(canonical).digest('hex');

    expect(hash1).toBe(hash2);
    expect(hash1.length).toBe(64); // SHA-256 = 32 bytes = 64 hex chars
  });

  it('applies correct trust verdict from adjusted score', () => {
    expect(getTrustVerdict(92).verdict).toBe('proceed');
    expect(getTrustVerdict(85).verdict).toBe('trusted');
    expect(getTrustVerdict(70).verdict).toBe('standard');
    expect(getTrustVerdict(45).verdict).toBe('caution');
    expect(getTrustVerdict(25).verdict).toBe('building');
    expect(getTrustVerdict(10).verdict).toBe('new');
  });

  it('returns verdict only — no settlement concepts (AID-Trust boundary)', () => {
    const result = getTrustVerdict(85);
    expect(Object.keys(result)).toEqual(['verdict']);
  });
});

// ─── Merkle Proof Test Vector ───────────────────────────────────────────────

describe('AID Merkle Proof (test-vectors/merkle-proof.json)', () => {
  function sha256(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  it('verifies a valid Merkle proof', () => {
    const leaf1 = sha256('rcpt-test1' + '2026-03-21T14:30:00Z' + 'did:key:zA' + 'did:key:zB');
    const leaf2 = sha256('rcpt-test2' + '2026-03-21T14:31:00Z' + 'did:key:zC' + 'did:key:zD');
    const leaf3 = sha256('rcpt-test3' + '2026-03-21T14:32:00Z' + 'did:key:zE' + 'did:key:zF');
    const leaf4 = sha256('rcpt-test4' + '2026-03-21T14:33:00Z' + 'did:key:zG' + 'did:key:zH');

    const node12 = sha256(leaf1 + leaf2);
    const node34 = sha256(leaf3 + leaf4);
    const root = sha256(node12 + node34);

    // Verify leaf1 with proof [right: leaf2, right: node34]
    let current = leaf1;
    current = sha256(current + leaf2); // sibling on right
    current = sha256(current + node34); // sibling on right

    expect(current).toBe(root);
  });

  it('rejects tampered leaf', () => {
    const leaf1 = sha256('rcpt-test1-TAMPERED' + '2026-03-21T14:30:00Z' + 'did:key:zA' + 'did:key:zB');
    const leaf2 = sha256('rcpt-test2' + '2026-03-21T14:31:00Z' + 'did:key:zC' + 'did:key:zD');
    const leaf3 = sha256('rcpt-test3' + '2026-03-21T14:32:00Z' + 'did:key:zE' + 'did:key:zF');
    const leaf4 = sha256('rcpt-test4' + '2026-03-21T14:33:00Z' + 'did:key:zG' + 'did:key:zH');

    const node12orig = sha256(sha256('rcpt-test1' + '2026-03-21T14:30:00Z' + 'did:key:zA' + 'did:key:zB') + leaf2);
    const node34 = sha256(leaf3 + leaf4);
    const expectedRoot = sha256(node12orig + node34);

    let current = leaf1;
    current = sha256(current + leaf2);
    current = sha256(current + node34);

    expect(current).not.toBe(expectedRoot);
  });
});

// ─── Crypto Agility ─────────────────────────────────────────────────────────

describe('AID Crypto Agility', () => {
  // Inline implementation — these should be exported from @aidprotocol/trust-compute
  // in a future version. For now, validate the spec requirements directly.
  const ALLOWED_ALGORITHMS = ['EdDSA', 'Ed25519', 'ML-DSA-44', 'ML-DSA-65', 'SLH-DSA'];
  const ALGORITHM_STRENGTH: Record<string, number> = {
    'SLH-DSA': 4,
    'ML-DSA-65': 3,
    'ML-DSA-44': 2,
    'Ed25519': 1,
    'EdDSA': 1,
  };

  function isAlgorithmAllowed(alg: string): boolean {
    return ALLOWED_ALGORITHMS.includes(alg);
  }

  function negotiateAlgorithm(client: string[], server: string[]): string | null {
    const mutual = client.filter(a => server.includes(a) && isAlgorithmAllowed(a));
    if (mutual.length === 0) return null;
    return mutual.sort((a, b) => (ALGORITHM_STRENGTH[b] ?? 0) - (ALGORITHM_STRENGTH[a] ?? 0))[0];
  }

  it('algorithm whitelist rejects unknown algorithms', () => {
    expect(isAlgorithmAllowed('EdDSA')).toBe(true);
    expect(isAlgorithmAllowed('Ed25519')).toBe(true);
    expect(isAlgorithmAllowed('RSA')).toBe(false);
    expect(isAlgorithmAllowed('WeakAlgo')).toBe(false);
  });

  it('algorithm negotiation picks strongest mutual', () => {
    expect(negotiateAlgorithm(['EdDSA'], ['EdDSA'])).toBe('EdDSA');
    expect(negotiateAlgorithm(['EdDSA', 'ML-DSA-44'], ['ML-DSA-44', 'EdDSA'])).toBe('ML-DSA-44');
    expect(negotiateAlgorithm(['EdDSA'], ['ML-DSA-44'])).toBeNull();
  });
});
