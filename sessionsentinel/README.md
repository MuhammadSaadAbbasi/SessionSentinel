# Sessionsentinel project overview

## Implemented detection rules R1-R6

## SMTP security notifications

Security notifications are persisted in the backend `notifications` table and delivered
through bounded SMTP STARTTLS connections. A provider outage does not undo a recorded
event or bypass rate limiting: the notification is marked `failed` and an administrator
can retry it from the incident detail screen.

Copy `backend/.env.example` to `backend/.env` and fill in the SMTP values. The real
`.env` file is ignored by Git.

For Gmail:

1. Enable two-step verification on the sender Google account.
2. Open **Google Account → Security → 2-Step Verification → App passwords**.
3. Create an app password for SessionSentinel and put the generated 16-character value
   in `SMTP_PASSWORD`; do not use the normal Google password.
4. Set `SMTP_EMAIL` to the sender account and `ADMIN_EMAIL` to the administrator inbox.

Start the backend from the repository's `sessionsentinel/backend` directory so the
configured database and environment are used:

```powershell
copy .env.example .env
python -m pip install -r requirements.txt
python seed.py
uvicorn main:app --host 0.0.0.0 --port 8000
```

Verification emails contain a time-limited, single-use link. The device is not added
to `trusted_devices` until `/verify-device` succeeds. IP-level rate limiting never
revokes existing session tokens.

### Detection and investigation

- Login failures are counted per account in a configurable window: five failures create a
  high-severity incident and ten failures escalate it to critical with temporary account locking.
- R1 incidents are updated rather than duplicated; R2 correlates later successful logins
  with the active failure sequence.
- Unfamiliar devices and previously unseen login IPs create R3 incidents. R4 holds a
  session when either follows an R1 sequence.
- R5 unauthorized reports revoke all sessions, require a password reset, and send a local alert.
- R6 identifies suspicious activity across more than three accounts sharing an IP,
  records affected accounts and timestamps, and applies IP-level rate limiting.
- Admins can view filtered incidents and an incident detail timeline at `/admin/incidents`.

### Response and audit controls

- Admins can change incident status through `/admin/incidents/{id}/status`.
- Admins can revoke a session through `/admin/sessions/{id}/revoke`; the token is rejected on the next request.
- Users can report an event through `/me/report` with `is_me: false`; all active sessions are revoked and a high-severity incident is created.
- Users can confirm an event with `is_me: true`; the device is trusted and the related open new-device incident is resolved.
- Unauthorized reports require a password reset through `POST /reset-password`; changing the password revokes all existing sessions.
- R1 escalation and account locks are audited, and R1 plus a successful new-device or unusual-location
  login becomes a high-risk held session.
- Security actions append entries to the SHA-256 hash-chained `audit_log` table.
- Unauthorized reports print a visible console alert through the local notifier adapter.
- Admins can list the audit log at `/audit` and verify its integrity at `/audit/verify`.
- Verification returns `{"status":"valid"}` or identifies the first broken entry.

### Frontends

- The demo site includes signup with transactional email verification, login, account and security activity, active sessions, 429 messaging, new-device verification, and email links to cancel individual sign-in sessions.
- Signup accounts remain pending until their single-use, hashed verification token is consumed. Verification and cancellation links are removed from the browser address bar before the frontend calls the API.
- The admin panel includes dashboard counts, incident filters/details, status actions, and an audit log integrity screen.

### Local M4 verification

```powershell
cd "C:\Users\Admin\Desktop\Session Sentinel\sessionsentinel\backend"
python seed.py
uvicorn main:app --host 0.0.0.0 --port 8000
```

Run the frontends in separate terminals:

```powershell
cd "C:\Users\Admin\Desktop\Session Sentinel\sessionsentinel\demo-site"
npm.cmd run dev

cd "C:\Users\Admin\Desktop\Session Sentinel\sessionsentinel\admin-panel"
npm.cmd run dev
```

Use the admin panel at `http://localhost:5174`, open an incident, change its status, then use **Audit log** and **Verify integrity**. To test user protection, sign in at `http://localhost:5173`, open **My Security**, and report a new-device event as unauthorized.

## M5 verification and stability

M5 adds regression coverage for the complete security flow:

- Brute-force R1: five failures create a high incident, ten failures escalate it to critical,
  and the account lock returns `429` with `retry_after`.
- Account isolation: an attack against one account does not block another account.
- R2: a successful login after an R1 sequence is investigated.
- R3: a successful login from a new device creates a `new_device` event and incident.
- Revoked and expired tokens are rejected with `401`.
- User unauthorized reports revoke all active sessions.
- Admin session revocation and incident status changes are audited.
- Audit tampering is detected and the first broken entry is reported.
- Frontends return users to login after a protected request receives `401`.

Validation commands:

```powershell
cd "C:\Users\Admin\Desktop\Session Sentinel\sessionsentinel"
python -m pytest backend\tests -q

cd "C:\Users\Admin\Desktop\Session Sentinel\sessionsentinel\demo-site"
npm.cmd run build
npm.cmd run lint

cd "C:\Users\Admin\Desktop\Session Sentinel\sessionsentinel\admin-panel"
npm.cmd run build
npm.cmd run lint
```

The backend regression suite includes the legacy M5/M6 scenarios plus focused R1/R6 rule tests.

## M6 presentation and M7 release package

The presentation and reproducible demonstration materials are in:

- [PRESENTATION.md](./PRESENTATION.md): architecture, security flow, CIA mapping,
  design decisions, limitations, and measured validation results.
- [DEMO_RUNBOOK.md](./DEMO_RUNBOOK.md): startup commands, test credentials,
  five-minute demonstration, and controlled audit-tamper verification.

M7 is treated as final release readiness because the original milestone plan
defines M0 through M6 only. The final package includes:

- Backend detection, investigation, response, and audit controls
- Working demo-site and admin-panel frontends
- M2-M5 regression coverage
- Reproducible build, lint, and test commands
- Documented limitations and safe demo boundaries
