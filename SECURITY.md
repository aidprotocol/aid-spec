# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in the AID Protocol specification or any `@aidprotocol` package, please report it responsibly.

**Email:** security@claw-net.org

**Do NOT:**
- Open a public GitHub issue for security vulnerabilities
- Discuss vulnerabilities in public channels before a fix is available

**We will:**
- Acknowledge receipt within 48 hours
- Provide an initial assessment within 7 days
- Work with you on a coordinated disclosure timeline

## Scope

This security policy covers:
- The AID Protocol Specification (`spec/`)
- `@aidprotocol/trust-compute` (npm)
- `@aidprotocol/mcp-trust` (npm)
- Test vectors (`test-vectors/`)

## Ed25519 Implementation Requirements

AID implementations MUST follow the Ed25519 security requirements in Section 12.2 of the specification:

- Use libraries that derive public keys internally (not separate parameters)
- Use library-level APIs, not CLI tools (CVE-2025-15469)
- If using libsodium, require version 1.0.20+ (CVE-2025-69277)
- Maintain an `allowedAlgorithms` whitelist

See the [MystenLabs unsafe Ed25519 library list](https://github.com/MystenLabs/ed25519-unsafe-libs) for libraries vulnerable to the Double Public Key Oracle Attack.

## Known Security Considerations

The specification documents 63 attack vectors with mitigations across Sections 20, 26, 32, 39, 41, 43, 44, and 45 of the engineering document. A summary is available in the specification's Security Properties section (Section 12).
