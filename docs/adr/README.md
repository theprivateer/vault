# Architecture Decision Records

One file per decision, numbered in order, never edited after acceptance — a decision that turns
out wrong gets a new ADR that supersedes it, so the reasoning trail stays intact.

Cryptographic decisions live in [../03-cryptographic-design.md](../03-cryptographic-design.md);
an ADR here records *why* a choice was made and what was rejected, not how it works.

| ADR | Title | Status |
| --- | --- | --- |
| [0000](0000-template.md) | Template | — |
| [0001](0001-zero-knowledge-architecture.md) | Zero-knowledge architecture and its consequences | Accepted |
| [0002](0002-pin-typescript-5.md) | Pin TypeScript to 5.x | Accepted |
| [0003](0003-argon2id-implementation.md) | Argon2id implementation: pure JS or WASM | **Open** — decided in Phase 1 |
