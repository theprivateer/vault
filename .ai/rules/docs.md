---
paths:
  - 'docs/**'
---

# Docs

## Read the design docs before changing crypto or schema
docs/ holds the full design: 01 decisions, 02 threat model, 03 cryptographic design, 04 data model, 05 the phased implementation plan, 06 testing strategy, adr/ decision records.

Any change to cryptography updates docs/03-cryptographic-design.md first, then the code. Any new column updates docs/04-data-model.md including its leakage note.

Ask of every change: what does the server learn that it did not learn before? If the answer is anything, it belongs in "Accepted leakage" in docs/02-threat-model.md or it gets designed out.

Work proceeds in phases (docs/05). Phase 0 is complete; Phase 1 is the crypto core.
