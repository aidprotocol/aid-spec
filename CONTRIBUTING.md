# Contributing to AID Protocol

Thank you for your interest in AID. Contributions are welcome.

## What to Contribute

- **Spec feedback**: Open an issue with the `spec` label
- **Test vectors**: Add vectors to `test-vectors/` with clear descriptions
- **Profile specs**: New transport profiles in `spec/profiles/`
- **Package improvements**: Bug fixes and features for packages in `packages/`
- **Security issues**: See [SECURITY.md](./SECURITY.md) for responsible disclosure

## Process

1. Fork the repo
2. Create a branch (`feat/description` or `fix/description`)
3. Make changes with clear commit messages
4. Open a pull request against `main`

## Guidelines

- Protocol spec changes require discussion in an issue first
- Test vectors must be deterministic and include expected outputs
- Package changes must not break existing published APIs
- All code uses MIT license; spec uses Apache 2.0

## Scope

This repo contains the **AID protocol specification** and **@aidprotocol packages**. The reference implementation (ClawNet) is maintained separately.

## Standards Work

AID is being submitted to DIF TAAWG. If you're interested in standards engagement, open an issue tagged `standards`.
