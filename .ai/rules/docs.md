---
paths:
  - 'docs/**'
---

# Docs

## Read the design docs before changing crypto or schema
docs/ holds the full design: 01 decisions, 02 threat model, 03 cryptographic design, 04 data model, 05 the phased implementation plan, 06 testing strategy, adr/ decision records.

Any change to cryptography updates docs/03-cryptographic-design.md first, then the code. Any new column updates docs/04-data-model.md including its leakage note.

Ask of every change: what does the server learn that it did not learn before? If the answer is anything, it belongs in "Accepted leakage" in docs/02-threat-model.md or it gets designed out.

Work proceeds in phases (docs/05). Do not record which phase is current here — it goes stale every
phase and a stale rule is worse than no rule. The Status section of the root README.md is the one
place that says what is built; update that and nothing else.

Docs describe what exists. Anything specified but not yet built says so directly under its heading,
and any security requirement without a passing test is marked outstanding rather than listed as
verified — a requirement that claims a test it does not have reads as evidence.

## Never change a heading that another doc links to
Cross-doc anchors are generated from heading text, so appending a status marker ("### Files (Phase 6, not yet built)") silently breaks every `#files` link pointing at it. Put status in an italic line *under* the heading instead, and keep the heading itself stable.

Anchors are not checked by any gate. After editing headings, verify links resolve before finishing.
