---
paths:
  - 'app/Console/Commands/**'
---

# Commands

## An operator job that cannot report fails loudly, and never overstates what it saw
`vault:audit-anchor`, `vault:anomalies` and `vault:verify-backup` share two conventions. Keep them.

**Unconfigured means failure, not a quiet exit.** A monitoring job that exits zero having had nowhere to send its findings leaves the operator believing they are watched over. Both mailing commands error and return FAILURE when their address is unset; `--print` is the escape hatch for running by hand.

**Say what was not checked.** `vault:verify-backup` closes by saying it only checked structure; `vault:preflight` closes by saying it only read configuration. A checker that implies more than it measured is worse than none.

`vault:anomalies` is four thresholds over a table and its wording says so. Do not dress it up as detection: the server cannot read anything these events refer to, so it cannot tell a busy afternoon from an exfiltration. Two checks (recovery-kit use, full export) deliberately have no threshold — one occurrence is the finding.

SQL gotcha, found by the Postgres CI job: `having('total', …)` on a select alias works on SQLite and throws on Postgres. Use `havingRaw('count(*) >= ?', …)`.
