# AID-Receipt Protocol Specification

> Version: 0.1-draft
> Status: Design phase (ships after AID-Trust has external adoption)
> Protocol 2 of the AID family

Bilateral, portable, Merkle-anchored receipts. Both parties sign. Both classify outcome.

*Spec to be written when Protocol 2 development begins. This is a placeholder.*

## Scope

AID-Receipt defines:
- DSIR format (DualSignedInteractionReceipt)
- OutcomeClassification enum
- Dual-party commitment logs
- Bloom filter log summaries
- Epoch compaction
- Liveness grace period
- Feedback endpoint (POST /aid/feedback — takes receiptId)
- Schema evolution policy
- Receipt-primary scoring enhancements to AID-Trust formula

AID-Receipt does NOT define:
- Trust scoring formula (see AID-Trust — AID-Receipt feeds it)
- Settlement modes (see AID-Settle)
- Identity management (see AID-Trust)

## Composability

AID-Receipt extends AID-Trust by:
- Mapping DSIRs to AID-Trust's abstract input classes (agreed DSIRs → "bilateral verified")
- Adding heartbeat extensions (supported receipt formats, commitment log endpoints)
- Enabling EigenTrust graph scoring (nodes=DIDs, edges=DSIRs)

See `protocols/composability.md` for cross-protocol requirements.

## Prerequisites

AID-Trust must be implemented (AID-Receipt depends on identity and scoring infrastructure).
