---
paths:
  - 'docs/**'
  - docs/05-implementation-plan.md
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

## Every phase ends with a "Carried forward" section, including the ones already done
When a phase closes, append a "Carried forward from Phase N" section naming what was built, what departed from the task list and why, and what was left undone.

This is not bookkeeping. Phases 5–11 each had one; 0–4 did not, and both items found in the post-Phase-11 sweep were in that half — a `dontFlash` list that drifted for eleven phases (F11), and task 9's "and email notification", which was simply never built. A task list with ticks and no prose cannot show you the clause that got dropped mid-sentence.

Say what is outstanding even when the answer is "nothing from this phase's own list".
