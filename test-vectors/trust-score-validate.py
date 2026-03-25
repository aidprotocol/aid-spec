"""
AID-Trust Cross-Language Test Vector Validation (Python)

Validates that Python produces identical trust scores and proof hashes
to the TypeScript reference implementation. Per Section 4.1.2, all
implementations MUST use IEEE 754 binary64 and roundHalfUp rounding.

Usage:
    python trust-score-validate.py

Requires: Python 3.8+ (no external dependencies)
"""

import json
import hashlib
import math
import sys
from pathlib import Path


def jcs_serialize(value) -> str:
    """JSON Canonicalization Scheme (RFC 8785) implementation."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        # Integers serialize as-is (no decimal point)
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JCS: non-finite numbers not supported")
        # ES2015 Number.toString() rules:
        # - No trailing zeros after decimal
        # - No unnecessary decimal point
        if value == 0.0:
            return "0"
        s = repr(value)
        # Python repr() matches ES2015 for IEEE 754 doubles
        return s
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True)
    if isinstance(value, list):
        return "[" + ",".join(jcs_serialize(v) for v in value) + "]"
    if isinstance(value, dict):
        # Keys sorted lexicographically (Unicode code point order)
        sorted_keys = sorted(k for k in value if value[k] is not None)
        entries = [json.dumps(k) + ":" + jcs_serialize(value[k]) for k in sorted_keys]
        return "{" + ",".join(entries) + "}"
    return ""


def round_half_up(x: float) -> int:
    """Round half up (Section 4.1.2 Step 5).

    CRITICAL: Do NOT use Python's round() — it uses banker's rounding.
    round(7.5) == 8 in Python (happens to match), but round(0.5) == 0 (differs from JS).
    """
    return int(math.floor(x + 0.5))


def compute_trust_score(
    success_rate: float,
    chain_coverage: float,
    attestation_count: int,
    manifest_adherence: float,
    weights: dict = None,
) -> dict:
    """Compute trust score per Section 4.1.2 deterministic algorithm."""
    if weights is None:
        weights = {"successRate": 40, "chainCoverage": 25, "volume": 20, "manifestAdherence": 15}

    # Step 1: Normalize volume
    volume = min(attestation_count / 1000.0, 1.0)

    # Step 2: Apply manifest default
    effective_manifest = manifest_adherence
    if attestation_count == 0 and manifest_adherence == 0:
        effective_manifest = 0.5

    # Step 3: Compute dimension products (each independently)
    d1 = success_rate * weights["successRate"]
    d2 = chain_coverage * weights["chainCoverage"]
    d3 = volume * weights["volume"]
    d4 = effective_manifest * weights["manifestAdherence"]

    # Step 4: Sum left-to-right (REQUIRED evaluation order)
    raw_score = ((d1 + d2) + d3) + d4

    # Step 5: Round half up (NOT banker's rounding)
    base_score = round_half_up(raw_score)

    # Step 6: Clamp
    base_score = max(0, min(100, base_score))

    # Proof hash
    inputs = {
        "successRate": success_rate,
        "chainCoverage": chain_coverage,
        "attestationCount": attestation_count,
        "manifestAdherence": manifest_adherence,
    }
    proof_data = {"inputs": inputs, "weights": weights, "score": base_score}
    canonical = jcs_serialize(proof_data)
    proof_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    return {
        "score": base_score,
        "proofHash": proof_hash,
        "intermediate": {
            "volume": volume,
            "d1": d1,
            "d2": d2,
            "d3": d3,
            "d4": d4,
            "rawScore": raw_score,
        },
        "jcsCanonical": canonical,
    }


def main():
    vectors_path = Path(__file__).parent / "trust-score.json"
    with open(vectors_path) as f:
        data = json.load(f)

    passed = 0
    failed = 0

    for vec in data["vectors"]:
        if vec["type"] == "negative":
            continue

        inp = vec["input"]
        result = compute_trust_score(
            success_rate=inp["successRate"],
            chain_coverage=inp["chainCoverage"],
            attestation_count=inp["attestationCount"],
            manifest_adherence=inp["manifestAdherence"],
        )

        expected = vec["expectedOutput"]
        inter = vec.get("intermediate", {})

        errors = []

        # Check score
        if result["score"] != expected["score"]:
            errors.append(f"score: got {result['score']}, expected {expected['score']}")

        # Check proof hash
        if result["proofHash"] != expected["proofHash"]:
            errors.append(f"proofHash: got {result['proofHash']}, expected {expected['proofHash']}")

        # Check intermediates
        for key in ["volume", "d1", "d2", "d3", "d4", "rawScore"]:
            if key in inter and result["intermediate"][key] != inter[key]:
                errors.append(f"intermediate.{key}: got {result['intermediate'][key]}, expected {inter[key]}")

        # Check JCS canonical (if provided)
        if "jcsCanonical" in inter and result["jcsCanonical"] != inter["jcsCanonical"]:
            errors.append(f"jcsCanonical mismatch")

        if errors:
            print(f"FAIL {vec['id']} ({vec['description']})")
            for e in errors:
                print(f"  {e}")
            failed += 1
        else:
            print(f"PASS {vec['id']} ({vec['description']})")
            passed += 1

    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
