# Security Policy

DuCaPra is a research prototype for cryptographically authenticated LLM-adjacent command execution.

The project is led from an idea-first, non-technical founder perspective and is intended to invite professional review. The security goal is to explore stronger foundations for private AI discussions and enterprise-grade execution rights, not to claim finished production assurance.

## Scope

In scope:

- Signed envelope validation
- Triangular Liveness Attestation verification
- Durable nonce and round-state handling
- Provenance-chain context assembly
- Pre-signing scanner bypasses with practical exploit paths

Out of scope:

- Universal prevention of all prompt injection in ordinary model text
- Model weight compromise
- Cloud KMS/HSM integrations not yet implemented
- Distributed liveness wire protocol not yet implemented

## Reporting

Open a private GitHub security advisory if available, or file an issue with a minimal reproduction that does not include live secrets.

## Current Hardening Status

- Ed25519 signatures
- Triangle-bound instruction signatures
- Restart-safe SQLite nonce/round state
- TTL and clock-skew checks
- Pre-signing prompt-injection scanner
- Tamper-evident hash-chained audit log

## Review Priorities

- Whether the cryptographic trust boundary is correctly scoped
- Whether the liveness model is useful for enterprise execution authorization
- How private conversation contents should be encrypted, stored, and revoked
- How key custody should work with KMS, HSMs, or trusted execution environments
- How non-technical users should safely configure and understand the system
