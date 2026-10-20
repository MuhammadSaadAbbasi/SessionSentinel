# SessionSentinel Presentation

## 1. Problem

SessionSentinel detects suspicious login activity on our own demo website,
explains why it is suspicious, and applies server-side corrective actions.

The system demonstrates:

- Brute-force detection and account-scoped throttling
- New-device detection
- Investigation timelines and risk assessment
- Session revocation
- User reporting of unauthorized activity
- Tamper-evident audit logging

## 2. Architecture

```text
demo-site (5173) ─┐
                  ├── Vite proxy ── FastAPI backend (8000) ── SQLite
admin-panel (5174)┘                         │
                                            ├── detection service
                                            ├── investigation agent
                                            ├── response service
                                            ├── notifier
                                            └── audit hash chain
```

The frontends only display data and send requests. Authentication,
authorization, detection, throttling, incident creation, session revocation,
and audit verification are performed by the backend.

## 3. Security flow

1. A test user logs in normally from the demo site.
2. `attacker/attack.py` sends eight failed attempts for one test account.
3. The eighth attempt receives `429` with `retry_after`.
4. A medium incident is created for that account only.
5. The admin panel displays the incident, evidence, risk level, and timeline.
6. An admin can investigate or resolve the incident and revoke a session.
7. The user can report an unfamiliar event as “This wasn't me”.
8. All active sessions are revoked and a high-severity incident is created.
9. The admin verifies the audit chain.

## 4. CIA mapping

| Goal | Demonstration |
|---|---|
| Confidentiality | A revoked token receives `401` immediately |
| Integrity | Editing an audit row is detected by `/audit/verify` |
| Availability | One attacked account is throttled while Sara can still log in |

## 5. Security design choices

- Passwords use Argon2id hashes; raw passwords are never stored or logged.
- Session tokens use secure random generation.
- Authorization is checked on every protected endpoint.
- Rate limits are scoped to the account, not globally.
- An unusual event is treated as evidence for review, not proof of compromise.
- Audit entries use SHA-256 chaining with a fixed genesis hash.
- Notifications use a visible local console adapter for the demo.

## 6. Limitations

- The notifier does not send real email; it prints a local alert.
- The investigation agent is intentionally rule-based and not an AI system.
- The demo uses SQLite and seeded test accounts.
- Password reset and extra verification are outside the current scope.
- Frontend UI validation is covered by builds/lint and manual runbook checks;
  there is no browser automation suite yet.

## 7. Results

Current automated validation:

- 15 backend tests passed
- Demo-site build and lint passed
- Admin-panel build and lint passed
- Python compilation passed
- Git diff validation passed
