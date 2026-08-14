# ADR-0003 — Argon2id implementation: pure JS or WASM

**Status:** Open — to be decided in Phase 1, with measurements
**Date raised:** 2026-08-14

This is a stub recording a known fork in the road, so that Phase 1 makes the decision
deliberately rather than discovering it. **Do not build key derivation on either option before
benchmarking.**

## Context

[../03-cryptographic-design.md](../03-cryptographic-design.md) specifies Argon2id at m=64 MiB,
t=3, p=1 as the password KDF, and names `@noble/hashes` as the intended implementation.

`@noble/*` was chosen for the crypto core because it is audited, pure TypeScript, dependency-free,
and — critically — needs no WebAssembly. A WASM implementation requires `'wasm-unsafe-eval'` in
`script-src`, which loosens the strict CSP that D10 and the `SecurityHeaders` middleware establish
as the primary XSS control.

Pure-JS Argon2id at these parameters is slow. It may miss the unlock budget:

- **Under 2 s on a modern laptop**
- **Under 5 s on a mid-range phone**

## The decision to make

If `@noble/hashes` meets the budget, keep it and the CSP stays strict.

If it does not, the options are:

1. **Swap to `hash-wasm`** behind the same interface. Fast, at the cost of `'wasm-unsafe-eval'`.
2. **Lower the parameters.** Cheapest to implement and the most dangerous — it directly weakens
   resistance to the offline attack in adversary A1, which is the single attack this KDF exists to
   resist. Would need explicit justification against current OWASP guidance.
3. **Accept a slower unlock.** Viable if the measured cost is closer to the budget than not;
   unlock is not a per-request operation.

## What Phase 1 must produce

- Measured timings on at least one laptop and one mid-range phone, written into this ADR.
- The decision, with its date and status changed to Accepted.
- If WASM wins: an update to `SecurityHeaders::BASE_DIRECTIVES` and the corresponding assertion in
  `tests/Feature/SecurityHeadersTest.php`, both referencing this ADR.

## Measurements

_To be filled in by Phase 1._

| Device | Implementation | m | t | p | Time |
| --- | --- | --- | --- | --- | --- |
| | | | | | |
