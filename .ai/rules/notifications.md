---
paths:
  - 'app/Notifications/**'
---

# Notifications

## Security alerts are out-of-band, synchronous, and a closed set
AccountSecurityAlert exists because every in-product signal that an account was taken sits behind the credential the taker now holds — including the activity feed the recovery entry was written for. Email is the only channel a successful takeover does not control.

Rules when touching it:
- Keep ALERTABLE tiny (recovery used, password changed). An alert for ordinary activity trains people to filter the one that matters.
- Never queue it. QUEUE_CONNECTION=database needs a worker; an alert silently waiting in a table is worse than none.
- A send failure must never fail the request — it runs after the session is granted, and broken SMTP must not become a broken recovery flow. Catch and log, with no address and no body.
- Failed attempts send nothing: an alert on a wrong guess floods an inbox by typing an address and confirms the account exists (SR6).
- No IP in the message. audit_events keeps only ip_hash.

tests/Feature/Auth/SecurityAlertTest.php.
