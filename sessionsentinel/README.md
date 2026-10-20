# Sessionsentinel project overview

## Implemented through M7

### Detection and investigation

- Login failures are counted per account in a configurable two-minute window.
- The eighth failure returns `429` with `retry_after` and creates a medium incident.
- Successful logins after an R1 sequence and unfamiliar devices are included in the investigation evidence.
- Admins can view filtered incidents and an incident detail timeline at `/admin/incidents`.

### Response and audit controls

- Admins can change incident status through `/admin/incidents/{id}/status`.
- Admins can revoke a session through `/admin/sessions/{id}/revoke`; the token is rejected on the next request.
- Users can report an event through `/me/report` with `is_me: false`; all active sessions are revoked and a high-severity incident is created.
- Users can confirm an event with `is_me: true`; the device is trusted and the related open new-device incident is resolved.
- Unauthorized reports require a password reset through `POST /reset-password`; changing the password revokes all existing sessions.
- R1 throttles are audited, and R1 plus a successful new-device login becomes a high-risk held session.
- Security actions append entries to the SHA-256 hash-chained `audit_log` table.
- Unauthorized reports print a visible console alert through the local notifier adapter.
- Admins can list the audit log at `/audit` and verify its integrity at `/audit/verify`.
- Verification returns `{"status":"valid"}` or identifies the first broken entry.

### Frontends

- The demo site includes login, account, security activity, active sessions, 429 messaging, new-device warnings, and a “This wasn't me” report action.
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

- Brute-force R1: seven failures return `401`, the threshold attempt returns `429`, and `retry_after` is present.
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

The M5/M6 regression suite currently passes with 16 backend tests.

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
