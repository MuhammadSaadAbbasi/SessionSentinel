# SessionSentinel: Project Context (for AI assistants and teammates)

Read this file fully before writing any code. Follow it exactly. If something is unclear, ask instead of guessing.

## 1. What we are building
SessionSentinel is a small information-security system. It detects suspicious login activity on our own demo website, investigates it with a rule-based agent, applies real corrective actions (rate limiting, session revocation, email alert), and keeps a tamper-evident (hash-chained) audit log.

Three parts, one shared backend:
- **backend/**: FastAPI + SQLite. ALL security logic lives here.
- **demo-site/**: plain HTML/CSS/JS. Login page, account page, "My Security" page (user side).
- **admin-panel/**: plain HTML/CSS/JS. Incident list/detail, response buttons, audit log viewer (admin side).
- **attacker/attack.py**: script that simulates brute-force attempts against OUR OWN test accounts only.

The websites only display data and send requests. The backend checks permissions on every request and performs every security action. A button that only changes a label is NOT a security control.

## 2. Hard rules
1. Never store or log raw passwords. Hash with Argon2id (`argon2-cffi`).
2. Never invent our own crypto. Use `hashlib.sha256` for the audit chain, `secrets.token_urlsafe` for session tokens.
3. Only our own test accounts and our own demo site. No real accounts, no third parties.
4. No paid APIs, no AI/LLM calls. The investigation agent is plain Python rules.
5. Secrets go in `.env` (never commit it). Never hardcode passwords or tokens.
6. Server-side authorization on every protected endpoint. Never trust the frontend.
7. Never lock an account permanently. Throttle with waiting times; real users must be able to recover.
8. Do not claim a feature works unless it is connected to real backend logic and has been run.
9. Keep it simple: no extra frameworks, no TypeScript, no React. Plain HTML + JS + `fetch`.

## 3. Folder structure
```
sessionsentinel/
├── attacker/attack.py
├── backend/
│   ├── main.py, config.py, database.py, models.py, schemas.py, security.py, deps.py, seed.py
│   ├── routers/    auth.py, me.py, admin.py, audit.py
│   ├── services/   detection.py, agent.py, response.py, audit_log.py, notifier.py
│   └── tests/      test_rate_limit.py, test_revoked_session.py, test_audit_tamper.py
├── demo-site/      index.html, account.html, security.html, css/, js/
└── admin-panel/    login.html, dashboard.html, incidents.html, incident.html, audit.html, css/, js/
```
`routers/` receive requests and call `services/`. Business logic goes in `services/`, not in routers.
`main.py` also serves the frontends: `/site` -> demo-site, `/admin` -> admin-panel (same origin, so no CORS problems). Run with `uvicorn main:app --host 0.0.0.0 --port 8000`.

## 4. Database tables (SQLAlchemy, SQLite)
- **users**: id, email (unique), password_hash, role ("user" or "admin"), created_at
- **events**: id, user_id (nullable for unknown email), email_tried, device_id, ip, type ("login_ok", "login_fail", "new_device", "session_revoked", ...), created_at
- **sessions**: id, user_id, token, device_id, created_at, revoked (bool)
- **trusted_devices**: id, user_id, device_id, first_seen
- **incidents**: id, user_id, severity ("low", "medium", "high"), status ("open", "investigating", "contained", "resolved", "false_positive"), explanation, created_at
- **audit_log**: id, action, actor, details, created_at, prev_hash, hash

Every event, session and incident carries the user_id, so each account is tracked separately. Counters are queries filtered by user_id (or device_id for device-level rules).

## 5. Detection rules (values live in config.py, never hardcoded)
- **R1**: 8 failed logins on one account within 2 minutes -> alert, throttle, incident (medium)
- **R2**: successful login after an R1 sequence -> raise priority
- **R3**: login from a device_id not in trusted_devices for that account -> flag for review
- **R4**: several indicators close together -> high-priority incident

One unusual event alone must NOT mark an account as compromised. Output is a risk assessment, not proof.

## 6. Rate limiting and response policy (starting values, configurable)
| Failed attempts in 2 min | Action |
|---|---|
| 1 to 2 | log only |
| 3 to 4 | short delay (1 to 2 s) |
| 5 | 1 minute wait |
| 8 (R1) | 15 minute wait, email the user, create incident (medium) |
| 15+ | 1 hour wait, incident high, admin alert, no repeat emails |

Waits have a maximum cap and decay after attempts stop. Return HTTP 429 with `retry_after` seconds.

After a successful login:
- known device, few failures: low, log only
- R1 + success on known device: medium, email, ask extra verification, block sensitive actions temporarily
- new device only: medium, email "was this you?"
- R1 + success + new device: high, revoke or hold session, require re-authentication, incident high, notify admin

User answer: "this was me" -> trust device, close incident. "this was not me" -> revoke ALL sessions, force password reset, incident high.
Changing a password must also revoke existing sessions.

## 7. Investigation agent (services/agent.py)
A plain Python function. Given an alert it: fetches related events for the user, builds a chronological timeline, assigns a risk level by explicit rules, writes a text explanation listing the evidence, and recommends an action. Example output:
```
Incident: Possible account compromise
Evidence: 8 failed logins within 2 minutes; successful login followed; unfamiliar device
Assessment: High priority
Recommended: revoke session, require re-authentication, notify the owner
```

## 8. Audit log (hash chain, services/audit_log.py)
Each entry stores `prev_hash` and its own `hash = sha256(prev_hash + action + actor + details + created_at)`. The first entry uses a fixed genesis value. `verify()` walks the chain and returns the id of the first broken entry, or "valid". Every security action (throttle, revoke, status change, email sent) writes an audit entry. Only append, never update or delete.

## 9. API contract
Auth header: `Authorization: Bearer <token>`. Errors: 401 invalid or revoked token, 403 not admin, 429 throttled (with `retry_after`).

| Endpoint | Request | Response |
|---|---|---|
| POST /login | email, password, device_id | token or error |
| POST /logout | | ok |
| GET /me/activity | | own recent events |
| GET /me/sessions | | own active sessions |
| POST /me/report | event_id, is_me | ok |
| GET /admin/incidents | filters: severity, status | incident list |
| GET /admin/incidents/{id} | | timeline, evidence, explanation, actions taken |
| POST /admin/sessions/{id}/revoke | | ok |
| POST /admin/incidents/{id}/status | status, note | ok |
| GET /audit | | audit entries |
| GET /audit/verify | | valid, or broken entry id |

A revoked session token must be rejected with 401 on the very next request.
Do not change this contract without telling the whole team first.

## 10. Who owns what (edit only your own folder)
- Member 3: `backend/`
- Member 1: `demo-site/` and `attacker/`
- Member 2: `admin-panel/`

Frontends can start with mock JSON that matches section 9, then switch to the real backend.

## 11. How the AI should work with us
- Do ONE small step at a time. Do not generate the whole project in one answer.
- Write complete, runnable code for that step, with comments, and a short explanation of what each part does (the team is learning).
- Say how to run and test the step.
- Include tests for both success and failure cases (e.g. revoked token must return 401).
- Do not add features that are not in this file.

## 12. Definition of done: the 5-minute demo
1. Real user logs in normally from device A.
2. Device B (attack.py) makes 8 wrong attempts on one test account -> throttled, incident created.
3. Admin panel shows the incident, timeline and explanation.
4. Admin revokes the session -> the old token is rejected on the next request.
5. An audit entry is edited by hand -> "Verify integrity" detects it.
Another user logs in normally during the attack (shows the other accounts are unaffected).
