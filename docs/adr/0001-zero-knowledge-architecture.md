# ADR-0001 — Zero-knowledge architecture and its consequences

**Status:** Accepted
**Date:** 2026-08-14

## Context

The 2017 application encrypted secrets at rest with a single application-wide key held in `.env`,
and decrypted them on the server before rendering. Compromise of that one key, or of the server
holding it, was total compromise of every user's data.

The rebuild is primarily a learning exercise in applied cryptography and security engineering.
That makes the interesting question not "how do we store secrets safely enough" but "what does it
actually take to build a system where the server cannot read the data at all" — including the
parts that are genuinely hard, and the costs that are usually designed around.

The full brief and per-decision rationale is in
[../01-brief-and-decisions.md](../01-brief-and-decisions.md).

## Decision

Decisions D1–D12 are accepted as the foundation of the rebuild:

| | Decision |
| --- | --- |
| D1 | True zero-knowledge E2EE. No escrow, no server-side decryption path, ever |
| D2 | Browser is the only client |
| D3 | Recovery kit, and honest permanent data loss if both password and kit are lost |
| D4 | Split-key authentication: Argon2id → KEK (client-only) + auth key (server sees a slow hash) |
| D5 | All metadata encrypted; search runs client-side |
| D6 | Item content is one encrypted JSON payload per record |
| D7 | Per-item keys wrapped by a per-vault key |
| D8 | Sharing by direct grant to fingerprint-verified public keys, with signed grants |
| D9 | Audit log, version history, TOTP and generators, one-time share links |
| D10 | Strict CSP, SRI, and a written threat model that admits what it cannot defend |
| D11 | Self-hosted, small trusted group; no organisation layer |
| D12 | Greenfield; no import from the 2017 database |

## Consequences

**Made easy.** A stolen database, a leaked backup and a compromised server at rest are all
survivable — there is no key in any of them that decrypts anything. Password changes re-wrap one
32-byte key rather than re-encrypting content. Revocation re-wraps item keys rather than
re-encrypting payloads.

**Made hard, and accepted:**

- No server-side search, sort, filter or pagination on anything users care about. The client
  decrypts a vault and indexes it in memory, with a scale ceiling that Phase 4 must measure.
- No password reset. The recovery kit is the only path, and losing both means the data is gone.
  This has to be stated in the product, not buried in documentation.
- No server-side rendering of secret content, no email containing a secret, no integrations.
- Sharing requires an asymmetric layer, out-of-band fingerprint verification, and a re-key on
  every revocation.
- Read-only access cannot be cryptographically enforced. Server policies stop a viewer writing;
  nothing stops them copying what they have decrypted.

**Ruled out entirely.** Any feature that requires the server to read user content. When such a
feature is requested, the answer is no, not "add an escrow key".

**Not defended.** A malicious or compromised server can serve JavaScript that exfiltrates the
master key. Strict CSP, SRI and Worker isolation reduce the odds of an incidental compromise
becoming a cryptographic one; none of them defend against the party controlling the bundle. See
adversary A3 in [../02-threat-model.md](../02-threat-model.md).

## Alternatives rejected

| Alternative | Why not |
| --- | --- |
| Hybrid: client-side crypto with server-side key escrow | Enables search and integrations, but a server compromise becomes total again — the exact failure being rebuilt away from |
| Server-side envelope encryption with a KMS | A real improvement on 2017 (per-vault keys, AEAD, genuine rotation) but the server still sees plaintext, so the trust boundary is unchanged |
| Organisations with admin escrow | Reintroduces "an administrator can read your data" after deliberately designing it out |
| OPAQUE / SRP instead of split-key auth | Strictly stronger against a malicious server, but no mature PHP implementation, and the gain is small next to A3, which dominates |
| Plaintext labels with encrypted values only | Simpler UX and real pagination, but names leak most of the information ("AWS root — production") |
