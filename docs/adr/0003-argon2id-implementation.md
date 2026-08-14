# ADR-0003 — Argon2id implementation: pure JS or WASM

**Status:** Accepted — `@noble/hashes`, pure JS
**Date raised:** 2026-08-14
**Date decided:** 2026-08-15

## Context

[../03-cryptographic-design.md](../03-cryptographic-design.md) specifies Argon2id at m=64 MiB,
t=3, p=1 as the password KDF. It runs in the browser on every unlock, so its cost is a UX budget
as much as a security parameter:

- **Under 2 s on a modern laptop**
- **Under 5 s on a mid-range phone**

`@noble/*` was the intended implementation for the crypto core: audited, pure TypeScript,
dependency-free, and needing no WebAssembly. The concern was that pure-JS Argon2id at these
parameters would miss the budget, forcing a swap to `hash-wasm` — which requires
`'wasm-unsafe-eval'` in `script-src` and so weakens the strict CSP established in Phase 0 as the
primary XSS control (D10, adversary A7).

This was flagged before implementation precisely so the choice would be made with measurements
rather than discovered late.

## Measurements

`npm run bench:argon2` (`benchmarks/argon2.mjs`), 5 runs after a warm-up, `dkLen=64`:

| Device | Implementation | m | t | p | Mean |
| --- | --- | --- | --- | --- | --- |
| Apple M1, 8 cores, node v22.23.2 | `@noble/hashes` 2.3.0 | 64 MiB | 3 | 1 | **731 ms** |
| Apple M1, 8 cores, node v22.23.2 | `@noble/hashes` 2.3.0 | 64 MiB | 2 | 1 | 487 ms |
| Apple M1, 8 cores, node v22.23.2 | `@noble/hashes` 2.3.0 | 32 MiB | 3 | 1 | 838 ms |
| Apple M1, 8 cores, node v22.23.2 | `@noble/hashes` 2.3.0 | 19 MiB | 2 | 1 | 152 ms |

731 ms at the specified parameters is comfortably inside the laptop budget, with room to spare —
the decision is not marginal, so no second implementation needed evaluating.

Node is a fair proxy for a desktop browser; both are V8. Two caveats stand:

- **The phone measurement is outstanding.** A mid-range phone is typically 2–4× slower than an M1,
  putting the estimate at roughly 1.5–3 s — inside the 5 s budget, but estimated rather than
  measured. Phase 2 builds the real unlock screen and should measure on a real device then.
- The measurement is single-run latency. Argon2id at p=1 is single-threaded by construction, so
  core count does not help.

## Decision

Use `@noble/hashes`' pure-JS `argon2id` at **m=64 MiB, t=3, p=1, dkLen=64**, run inside the crypto
Web Worker so the main thread stays responsive and can show real progress.

The CSP keeps `script-src 'nonce-…' 'strict-dynamic'` with **no `'wasm-unsafe-eval'`**.

## Consequences

The whole crypto dependency surface stays three audited, pure-TypeScript packages with no
transitive dependencies, no post-install scripts and no WASM — which also keeps the supply-chain
story (adversary A10) small enough to read end to end.

Unlock costs roughly three quarters of a second of blocked Worker time on good hardware. The UI
must show progress rather than appear frozen, and must not run the KDF speculatively.

Revisit if: the phone measurement comes in above 5 s; parameters are raised (the per-user
`kdf_params` column exists exactly so they can be); or `@noble/hashes` regresses on performance.
Any of those reopens the WASM question, and reopening it means a new ADR, not an edit to this one.

## Alternatives rejected

| Alternative | Why not |
| --- | --- |
| `hash-wasm` (WASM Argon2) | Faster, but costs `'wasm-unsafe-eval'` in `script-src`. Unjustifiable when the pure-JS path already meets the budget by a wide margin |
| Lower the parameters | The most dangerous option. Directly weakens resistance to the offline attack in adversary A1, which is the only attack this KDF exists to resist. Unnecessary — 731 ms is not a problem to solve |
| Raise parameters, since there is headroom | Tempting, but 64 MiB is already meaningful on a memory-constrained phone, and the phone figure is unmeasured. Revisit once real device numbers exist |
