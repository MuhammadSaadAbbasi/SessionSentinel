# SessionSentinel Demo Runbook

## Start the system

Use three terminals:

```powershell
cd "C:\Users\Admin\Desktop\Session Sentinel\sessionsentinel\backend"
python seed.py
uvicorn main:app --host 0.0.0.0 --port 8000
```

```powershell
cd "C:\Users\Admin\Desktop\Session Sentinel\sessionsentinel\demo-site"
npm.cmd run dev
```

```powershell
cd "C:\Users\Admin\Desktop\Session Sentinel\sessionsentinel\admin-panel"
npm.cmd run dev
```

Open:

- Demo site: `http://localhost:5173`
- Admin panel: `http://localhost:5174`
- Backend health: `http://localhost:8000/health`

Test accounts:

- User: `ali@test.com` / `Test@12345`
- User: `sara@test.com` / `Test@12345`
- Admin: `admin@test.com` / `answerable`

## Five-minute demonstration

1. Open the demo site and log in as Sara.
2. Open **My Security** and show the active session.
3. In another terminal run:

   ```powershell
   cd "C:\Users\Admin\Desktop\Session Sentinel\sessionsentinel"
   python attacker\attack.py ali@test.com 8
   ```

4. Show seven `401` responses followed by `429`.
5. Log in to the admin panel as the admin account.
6. Open **Incidents** and open the Ali incident.
7. Show the evidence, risk assessment, recommendation, and timeline.
8. Click **Investigate** or **Resolve**.
9. Open **Audit log** and click **Verify integrity**.
10. Return to the demo site and show that Sara was not blocked.
11. Log in as a user from a second device ID, then use **This wasn't me**.
12. Show that the user token is revoked and the next protected request returns
    `401`.

## Tamper verification

For a controlled local demonstration only:

1. Stop the backend.
2. Make a copy of `backend\sessionsentinel.db`.
3. Modify one `audit_log.details` value using a SQLite tool.
4. Restart the backend and use **Verify integrity**.
5. The response must identify the first broken entry.
6. Restore the database copy after the demonstration.

Never run the attack script against real accounts or third-party services.
