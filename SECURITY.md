# Security policy

This is a self-hosted, invite-only secret manager built as a learning exercise in doing
zero-knowledge encryption properly. It is used with real credentials, so reports are taken
seriously; it is also not a funded product, so the honest promises below are modest ones.

## Reporting a vulnerability

Open a **private security advisory** through GitHub's *Security → Report a vulnerability* on this
repository. That keeps the report out of the public issue tracker until there is a fix.

Please do not open a public issue for anything that would let somebody read another person's
secrets, forge an audit entry, or take over an account.

**What helps most:** the version or commit, what you did, what happened, and what you expected. A
proof of concept is welcome and never required — a clear description of the mechanism is worth more
than a script.

**What to expect:** an acknowledgement within a week, an assessment within two, and a fix or a
written decision not to fix. Nothing is paid for reports. If you would like credit, say so and you
will be named in the commit and the release notes; if you would rather not be, that is the default.

Disclose publicly whenever you like once a fix has shipped, or after 90 days if one has not — and
please say so in the advisory rather than waiting silently, because a report that goes quiet is
indistinguishable from a report that was fixed.

## What is in scope

Anything that breaks one of the ten security requirements in
[docs/02-threat-model.md](docs/02-threat-model.md#security-requirements). In particular:

- **Any path by which the server could obtain plaintext or a key.** This is the central claim of
  the design and the most valuable thing to break. A single `decrypt()` reaching production would
  be the whole project failing.
- Reading, writing or deleting data belonging to a vault you are not a member of, or acting beyond
  the role you were granted.
- Moving a ciphertext between records or fields without the AEAD tag failing.
- Forging, reordering, deleting or silently modifying an audit entry.
- Anything that reveals whether an account exists to somebody who cannot already see the member
  list — including by response time, not only by response body.
- Key material reaching `localStorage`, `sessionStorage`, IndexedDB, a cookie, an Inertia page prop
  or a log.
- Cross-site scripting, CSRF, or a way past the content security policy and its Trusted Types
  enforcement.
- A share link that can be opened more times than it was allowed to, or whose token or key can be
  recovered from the server.

## What is out of scope, and why

**A compromised server serving modified JavaScript.** This is adversary A3 in the threat model, it
is not defended against, and it cannot be — the encryption runs in code this same server delivers.
It is stated in the product itself at `/security` rather than only in the repository. Reports
demonstrating it are correct and already known; reports of a *new* way to reach that position (an
injection, a supply-chain path into the bundle, a way to modify assets without server access) are
very much in scope.

**A compromised user device.** A keylogger or a malicious browser extension defeats everything
here, by design and unavoidably.

Also out of scope: missing headers with no demonstrated impact, output from an automated scanner
with no analysis attached, denial of service through volume, social engineering, and anything
requiring physical access to a user's unlocked machine.

## Known, accepted, and written down

These are deliberate and reporting them will get you a link back to here:

- There is **no password reset and no account recovery of last resort**. Losing both the master
  password and the recovery kit means the data is permanently unreadable, including by whoever runs
  the server.
- The server learns a substantial amount of **metadata**: how many items exist, roughly how large
  each one is, when each changed, and who shares what with whom. The full list is
  [docs/02-threat-model.md § Accepted leakage](docs/02-threat-model.md#accepted-leakage).
- **File sizes are not padded** and are visible to the byte. Item payloads are padded into buckets.
- **Archived versions of a secret can never be re-encrypted**, because an archive that can be
  rewritten is a rollback channel for a credential somebody rotated because it leaked.
- The **identity directory confirms whether a handle exists** to any signed-in user. Sharing
  requires that lookup, and this is a small invited group where the member list is not the secret.

## Supported versions

The tip of `main`, deployed. There are no release branches and no backports.
