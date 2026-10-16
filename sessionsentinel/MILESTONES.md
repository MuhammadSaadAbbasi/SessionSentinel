# SessionSentinel: 7-Day Milestone Plan (3 members, kaam ek saath, conflict ke baghair)

Roles: **Member 1** = `demo-site/` + `attacker/` (+ `notifier.py` on Day 5). **Member 2** = `admin-panel/`. **Member 3** = `backend/` (baqi sab files).
Sab AI se code likhwa rahe hain (vibe coding), is liye har milestone ke end par **"Done when"** check chalana zaroori hai. Jo chala nahi, wo bana nahi.

---

## 1. Conflict kaise nahi hoga (4 rules)

**Rule 1: Har banda sirf apna folder edit kare.**

| Folder / file | Owner |
|---|---|
| `backend/` (sab files) | Member 3 |
| `backend/services/notifier.py` | Member 1 (sirf Day 5, Member 3 us din ye file na chheray) |
| `demo-site/`, `attacker/` | Member 1 |
| `admin-panel/` | Member 2 |
| `PROJECT_CONTEXT.md`, `MILESTONES.md` | Leader (sirf group ki ijazat se badle) |

Backend ki shared files (`models.py`, `schemas.py`, `config.py`, `main.py`) sirf Member 3 badalta hai. Member 1 ya 2 ko kuch naya field ya endpoint chahiye to **group mein message** karo, khud backend file mat chheray.

**Rule 2: Contract pehle, code baad mein.** Frontends `PROJECT_CONTEXT.md` section 9 ke mutabiq banate hain. Backend wahi format bhejta hai. Contract badalna ho to pehle group ko batao.

**Rule 3: Mock data se shuru.** Frontends backend ka intezar nahi karte. Har frontend mein `src/mock/` folder rakho jis mein contract jaisa JSON ho, aur `src/api.js` mein ek switch `USE_MOCK = true`. Backend ka endpoint tayyar ho to `false` kar do. Ye switch sirf `api.js` mein ho, pages mein nahi.

**Rule 4: Git ka daily rhythm.**
```
git pull origin main          # kaam shuru karne se pehle
(chhota kaam, chala ke dekho)
git add .
git commit -m "kya kiya"
git push origin main          # push se pehle phir git pull
```
Chhote commits, din mein 3 se 4 baar. Akhri din merge karne ka intezar mat karo. Push ke baad group mein "pushed: <kya>" likho.

---

## 2. Roz ka rhythm

| Waqt | Kaam |
|---|---|
| Subah | `git pull`, 10 minute ki call: kal kya hua, aaj kya, kahan atke ho |
| Dopahar | **Integration check** (neeche har din likha hai): teeno ka kaam jor ke chalao |
| Raat | `git push`, group mein status |

Atak jao to **2 ghante se zyada akele mat jhoojho**, group mein pucho.

---

## 3. Milestones (functionality ke hisaab se)

### M0: Foundation (Day 1)
Maqsad: teeno parts chalte hon, database aur users ready hon, pages ke raaste bane hon.

| Member 3 (Backend) | Member 1 (demo-site) | Member 2 (admin-panel) |
|---|---|---|
| `database.py`, `models.py` (6 tables), `security.py` (Argon2, token), `seed.py` (5 users + 1 admin), `main.py` mein `/health` aur routers include | `App.jsx` mein routes (`/`, `/account`, `/security`), 3 khali pages, `api.js` + `USE_MOCK`, `src/mock/*.json` | `App.jsx` mein routes (`/`, `/dashboard`, `/incidents`, `/incidents/:id`, `/audit`), khali pages, navbar, `api.js` + `USE_MOCK`, `src/mock/*.json` |

**Done when:**
- `curl http://localhost:8000/health` par `ok`
- `python seed.py` chala ke database mein users bane hain
- Dono frontends par `5173/health` aur `5174/health` par `ok`, aur pages ke beech navigate hota hai

**Integration check (raat):** teeno apna kaam push karo aur ek doosre ka kaam pull karke chalao.

### M1: Authentication aur sessions (Day 2)
Maqsad: asli user login kare, session token mile, logout ho, apni activity dikhe.

| Member 3 | Member 1 | Member 2 |
|---|---|---|
| `POST /login` (Argon2 check, device_id, session banana, event save: `login_ok` ya `login_fail`), `POST /logout`, `deps.py` (token se user, **revoked token par 401**, admin check par 403), `GET /me/activity`, `GET /me/sessions` | Login page asli backend se, token `localStorage` mein, Account page (user ka naam), logout button, `device_id` banana (ek baar random banao, `localStorage` mein rakho), Security page par recent logins list | AdminLogin page (admin ke credentials, normal user ko "not allowed"), Dashboard ka layout (counts mock se), Incidents list ka UI (table, filter bar) mock data se |

**Done when:**
- Browser se `ali` login kare to Account page khule
- Galat password par error dikhe aur database mein `login_fail` event bane
- Logout ke baad purana token `/me/activity` par **401** de
- Admin login se admin page khule

**Integration check:** demo-site se login karo, phir `events` table mein record dekho.

### M2: Detection aur rate limiting (Day 3)
Maqsad: attack pakra jaye aur roka jaye.

| Member 3 | Member 1 | Member 2 |
|---|---|---|
| `config.py` mein thresholds, `detection.py`: **R1** (8 fails in 2 min), **R2** (success after R1), **R3** (naya device, `trusted_devices` table), rate limit `/login` mein (**429 + retry_after**), incident record banana | `attacker/attack.py`: arguments (email, number of attempts, URL), Login page par 429 dikhana ("X seconds baad try karo"), Security page par "new device" nishani | Incident Detail page ka poora UI mock data se: **timeline component**, evidence list, explanation box, severity badge |

**Done when:**
- `python attack.py ali 8` chalane ke baad ali ke liye **429** milta hai
- `incidents` table mein ek incident ban chuka hai
- **Sara ka login us waqt normal chalta hai** (doosre account par asar nahi)

**Integration check:** attack chala ke database mein incident dekho.

### M3: Investigation agent aur incident views (Day 4)
Maqsad: incident ki wajah samajh aaye aur admin ko nazar aaye.

| Member 3 | Member 1 | Member 2 |
|---|---|---|
| `agent.py` (related events nikalna, timeline, risk level, explanation text, recommended action), `GET /admin/incidents` (filters: severity, status), `GET /admin/incidents/{id}` | Security page: sessions list, "this wasn't me" button ka UI (abhi mock), polish | `USE_MOCK = false` kar ke Incidents list aur Incident Detail **asli data** se jorna, Dashboard counts (open incidents, severity) asli data se |

**Done when:**
- Attack ke baad admin panel mein incident list mein nazar aata hai
- Detail page par timeline aur explanation ("8 failed logins within 2 minutes...") dikhti hai
- Dashboard ke counts database se match karte hain

**Integration check:** attack chalao, admin panel refresh karo, incident dekho.

### M4: Response actions aur audit log (Day 5)
Maqsad: asli corrective action aur tamper-proof record.

| Member 3 | Member 1 | Member 2 |
|---|---|---|
| `response.py` (session revoke, status change), `audit_log.py` (**hash chain**: add + verify), har action audit mein, `POST /admin/sessions/{id}/revoke`, `POST /admin/incidents/{id}/status`, `POST /me/report` (**"not me"** par saare sessions revoke), `GET /audit`, `GET /audit/verify` | `notifier.py`: email (Gmail SMTP, `.env` se App Password) ya console print. "This wasn't me" button asli endpoint se. 401 aaye to login page par bhejna | Incident Detail par **Revoke** aur **Status** buttons (confirmation ke saath), `AuditLog` page, **Verify Integrity** button (valid ya broken entry id dikhaye) |

**Done when:**
- Admin revoke dabaye to purana token agli request par **401** de
- Har action `audit_log` table mein aaye, aur `/audit/verify` par `valid`
- Database mein ek audit entry **haath se badlo** to verify **broken** bataye
- User "not me" dabaye to uske sessions revoke hon

**Integration check:** pura flow chalao: attack, incident, revoke, audit verify.

### M5: Testing aur bug fixing (Day 6)
**Feature freeze subah se.** Naye features nahi, sirf bugs.

| Member 3 | Member 1 | Member 2 |
|---|---|---|
| `tests/`: `test_rate_limit.py`, `test_revoked_session.py`, `test_audit_tamper.py` chalana aur theek karna, bugs | Attack scenarios (normal user, brute force, naya device, success after fails), **network check (E)** doosre device se, bugs | Admin panel ke bugs, empty states aur error messages, **teeno mil ke 5-minute demo** poora chalao |

**Done when:** 5-minute demo bina ruke chalta hai (neeche "Demo script").

### M6: Presentation (Day 7)
| Sab | Kaam |
|---|---|
| Member 1 | Slides: problem, architecture, demo flow |
| Member 2 | Slides: CIA triad, results, limitations; README |
| Member 3 | Metrics (kitne attempts par kya hua, response time), tamper test ka saboot |
| Teeno | **Demo 2 baar rehearse**, backup: screenshots ya screen recording |

---

## 4. Demo script (5 minute)
1. Device A par real user (`sara`) normal login.
2. Device B par `attack.py` se `ali` par 8 galat attempts: **429** aata hai.
3. Admin panel: incident, timeline, explanation.
4. Admin revoke dabaye: purana token **401** de.
5. Audit entry edit karo: **Verify Integrity** pakre.
6. Dikhao ke **sara** attack ke dauran normal login karti rahi.

CIA mapping: revoke test (Confidentiality), hash chain verify (Integrity), throttle plus sara ka normal login (Availability).

## 5. Agar peeche reh jao (kya kaato)
Is order mein chhoro: (1) asli email, console print kaafi, (2) R3 naya device, (3) device-level detection, (4) Dashboard ke charts. **Kabhi mat chhoro:** login, R1 plus 429, incident plus explanation, session revoke, audit hash chain plus verify.

## 6. AI se code likhwane ki guide (vibe coders ke liye)

**Har prompt ka template:**
```
Read PROJECT_CONTEXT.md. I am Member <1/2/3>.
Task: <ek chhota kaam, jaise "write POST /login">
Only edit these files: <file list>
Do not change the API contract.
Write complete code, explain each part in simple words,
and tell me how to run and test it.
```

**Rules:**
1. **Ek prompt, ek chhota kaam.** "Poora backend bana do" mat likho.
2. **Har code chala ke dekho.** Chala nahi to poora error AI ko paste karo.
3. **Jo code samajh na aaye, AI se kaho "explain line by line".** Presentation mein sawal aayenge.
4. Chala hua code **foran commit** karo, phir agla kaam.
5. AI ke "ye kaam kar raha hai" par bharosa mat karo, **khud test karo** (curl, browser, `tests/`).
6. AI ko naye libraries ya TypeScript ya bara refactor mat karne do.
7. **Security code ke liye khaas ehtiyat:** password hash `argon2-cffi` se ho, token `secrets.token_urlsafe`, revoked token par 401, audit chain `hashlib.sha256`. Aur check karo ke password kahin print ya log to nahi ho raha.
8. `.env` aur secrets AI chat mein paste mat karo.

## 7. Pehla kaam (abhi)
1. Teeno `git pull`, aur `PROJECT_CONTEXT.md` ke saath A se D check chalao.
2. M0 ke apne column ka pehla chhota task shuru karo.
