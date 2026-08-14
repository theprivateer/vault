# Vault — Design & Implementation Plan

A ground-up rebuild of the 2017 Vault app as a **zero-knowledge, end-to-end encrypted** secret manager.

The 2017 app encrypted secrets at rest with a single application-wide key and decrypted them
on the server before rendering. This rebuild moves the trust boundary: **the server stores
ciphertext and wrapped keys, and never holds a key capable of decrypting them.**

## Read in this order

| Doc | What it covers |
| --- | --- |
| [01 — Brief & Decisions](01-brief-and-decisions.md) | Goals, scope, the ten settled decisions and their rationale |
| [02 — Threat Model](02-threat-model.md) | Assets, adversaries, what is and is not protected, accepted risks |
| [03 — Cryptographic Design](03-cryptographic-design.md) | Key hierarchy, primitives, envelope format, every protocol flow |
| [04 — Data Model](04-data-model.md) | Schema, what each column leaks, migration notes |
| [05 — Implementation Plan](05-implementation-plan.md) | **The phases.** 13 phases, each with deliverables and exit criteria |
| [06 — Testing & CI](06-testing-and-ci.md) | Test strategy, the leak canary, CI gates |
| [adr/](adr/) | Decision records — why a choice was made, and what was rejected |

## The one-paragraph summary

A user's password is stretched with Argon2id in the browser into two independent keys: a
key-encryption key that never leaves the device, and an auth key that is all the server ever
sees. The KEK unwraps a random per-account **User Key**, which in turn unwraps the user's
X25519 and Ed25519 private keys. Each vault has a random **Vault Key**, sealed individually to
each member's X25519 public key. Each item (secret, lockbox, file) has its own **Item Key**
wrapped by the Vault Key, so revocation and rotation cost a re-wrap of 32-byte blobs rather
than a re-encryption of all content. Every ciphertext is bound by AEAD associated data to the
record it belongs to, so a malicious server cannot move a ciphertext from one field or row to
another. Item content is a single encrypted JSON payload, so names, notes and types are all
opaque to the server; search happens in the browser.

## Stack

- **Backend** — Laravel 13, PHP 8.4 (`ext-sodium` built in), Pest 5
- **Frontend** — Inertia v3 + Vue 3 + TypeScript (strict), Tailwind 4, Vite 8
- **Crypto** — `@noble/ciphers`, `@noble/curves`, `@noble/hashes` in the browser; WebCrypto for
  RNG and bulk file encryption. Nothing on the server.

## Status

**Phase 0 (foundations & guardrails) complete.** Inertia v3 + Vue 3 + TypeScript strict, a
strict nonce-based CSP enforced from the first render, Larastan at max level, and CI gating every
check. Next: [Phase 1 — the crypto core](05-implementation-plan.md#phase-1--crypto-core-library),
which begins by benchmarking Argon2id ([ADR-0003](adr/0003-argon2id-implementation.md)).
