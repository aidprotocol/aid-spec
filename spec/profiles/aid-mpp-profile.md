# AID-MPP Profile

**Integration point:** Stripe MPP session metadata

See Section 13.4 of the [AID Protocol Specification](../aid-protocol-v1.md) for the interoperability note.

## Overview

MPP (Machine Payments Protocol, launched March 18, 2026) provides session-based streaming micropayments. AID trust headers compose naturally with MPP sessions:

- **Without AID:** Standard MPP session with spending limit
- **With AID:** Trust-gated session limits — higher trust = higher spending cap

## Status

This profile is planned for a future version of the specification. The AID trust headers work identically regardless of whether the payment happens via x402 or MPP.

MPP is backwards-compatible with x402, so the AID-x402 Profile applies to MPP sessions consuming x402 services.
