# ADR-0002 — Pin TypeScript to 5.x

**Status:** Accepted
**Date:** 2026-08-14

## Context

TypeScript 7 — the Go-based compiler rewrite — is the current `latest` on npm, and installing
`typescript` unpinned during Phase 0 resolved to 7.0.2.

`typescript-eslint@8` declares a peer range of `>=4.8.4 <6.1.0` and refuses to install alongside
it. `vue-tsc@3` accepts `>=5.0.0` and would have worked either way.

The choice was therefore between the newest compiler with no type-aware linting, or TypeScript
5.9 with the full lint toolchain.

## Decision

Pin `typescript` to `^5.9`.

## Consequences

Type-aware ESLint rules are available, which matters more here than compiler speed. Two of them
are load-bearing for this project specifically:

- `@typescript-eslint/no-floating-promises` — the Phase 1 crypto Worker exposes an entirely async
  API. An unawaited decrypt would surface as a silently missing value rather than the loud error
  SR3 requires.
- `@typescript-eslint/no-misused-promises` — the same hazard in event handlers and Vue lifecycle
  hooks.

The cost is slower type checking than TS 7 would give, on a codebase small enough that it does not
yet matter, and being a major version behind.

Revisit when `typescript-eslint` ships TypeScript 7 support. This is a temporary pin on an
ecosystem gap, not a considered rejection of TS 7.

## Alternatives rejected

| Alternative | Why not |
| --- | --- |
| TypeScript 7 without `typescript-eslint` | Loses the async-safety rules in the one part of the codebase where an unhandled promise is a security bug, not a papercut |
| TypeScript 7 with `--legacy-peer-deps` | Installs a combination the maintainers say does not work; failures would surface as confusing parser errors rather than a clear refusal |
| Drop type-aware linting, rely on `vue-tsc` alone | `vue-tsc` checks types; it does not check for floating promises or misused async handlers |
