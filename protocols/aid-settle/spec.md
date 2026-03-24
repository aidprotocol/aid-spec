# AID-Settle Protocol Specification

> Version: 0.1-draft
> Status: Design phase (ships when AID-Receipt adopters want trust-gated pricing)
> Protocol 3 of the AID family

Trust scores determine how you pay. Higher trust = lower price + deferred settlement.

*Spec to be written when Protocol 3 development begins. This is a placeholder.*

## Scope

AID-Settle defines:
- Settlement modes (immediate, standard, batched, deferred)
- Trust-gated pricing (verdict → discount + settlement mode mapping)
- EIP-3009/EIP-2612 USDC settlement
- Credit limits, burst detection, permit health checks
- 402 response headers (PAYMENT-REQUIRED, X-AID-TRUST-GATE, X-AID-PRICING-TIERS)
- Avoid flag effects (prepay only, base price, no discounts)
- USDC pause detection + gas price circuit breaker

AID-Settle does NOT define:
- Trust scoring (see AID-Trust)
- Receipt format (see AID-Receipt)
- Verdicts (see AID-Trust — AID-Settle consumes them)

## Composability

AID-Settle extends AID-Trust by:
- Mapping verdicts to settlement modes + pricing discounts
- Adding heartbeat extensions (pricing tiers, settlement capabilities, payment chains)
- Defining avoid flag EFFECTS (AID-Trust defines and sets the flag)

See `protocols/composability.md` for cross-protocol requirements.

## Prerequisites

AID-Trust must be implemented. AID-Receipt recommended (receipts are settlement evidence).
