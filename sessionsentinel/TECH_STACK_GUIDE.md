# SessionSentinel: Tech Stack Guide (kaun sa part, kaun si language)

## 1. Ek nazar mein

| Part | Language | Framework / Tool | Owner |
|---|---|---|---|
| `backend/` | **Python** | FastAPI, SQLAlchemy, SQLite | Member 3 |
| `demo-site/` | **JavaScript (JSX) + CSS + HTML** | React (Vite), React Router | Member 1 |
| `admin-panel/` | **JavaScript (JSX) + CSS + HTML** | React (Vite), React Router | Member 2 |
| `attacker/attack.py` | **Python** | `requests` library | Member 1 |
| Database | **SQL** (SQLAlchemy ke zariye, direct SQL likhna zaroori nahi) | SQLite file | Member 3 |

Koi paid API nahi. Koi AI/LLM API nahi. TypeScript nahi, sirf JavaScript.

## 2. Har part mein kya hota hai

### Backend (Python)
- Login, session token, password hashing (`argon2-cffi`)
- Detection rules, rate limiting, investigation agent
- Session revoke, email alert, hash-chained audit log
- Sab security decisions yahin hote hain

Packages (`backend/requirements.txt`): `fastapi`, `uvicorn`, `sqlalchemy`, `argon2-cffi`, `python-dotenv`

### Demo site (React + JavaScript)
- Pages: Login, Account, Security (recent logins, sessions, "this wasn't me" button)
- Backend ko `fetch()` se call karta hai
- Sirf dikhata hai aur request bhejta hai, security logic nahi

### Admin panel (React + JavaScript)
- Pages: AdminLogin, Dashboard, Incidents, IncidentDetail, AuditLog
- Buttons: revoke session, status change, verify audit log
- Sirf dikhata hai aur request bhejta hai, security logic nahi

### Attacker script (Python)
- Apne hi test accounts par galat password ke attempts bhejta hai
- Sirf apni demo site par, kisi aur par kabhi nahi

## 3. Teeno parts kaise connect hote hain

```
Browser (demo-site :5173)  ──┐
                             ├── fetch('/login') ──▶ Vite proxy ──▶ Backend :8000 ──▶ SQLite
Browser (admin-panel :5174) ─┘
attack.py (Python) ───────────── http://<laptop-IP>:8000/login ──▶ Backend
```

Frontends ki `vite.config.js` mein proxy lagi hoti hai, is liye React mein sirf `/login`, `/me/activity` jaise paths likhte hain, IP nahi, aur CORS ka masla nahi aata.

| Cheez | Port |
|---|---|
| Backend (FastAPI) | 8000 |
| demo-site (Vite) | 5173 |
| admin-panel (Vite) | 5174 |

## 4. Setup (ek baar)

**Sab ke liye:** Git, VS Code.
**Member 1 aur 2 ke liye:** Node.js (LTS version).
**Member 3 aur Member 1 (attacker) ke liye:** Python 3.

Repo clone karne ke baad:

```
# Backend
cd backend
python -m venv venv
venv\Scripts\activate          (Mac/Linux: source venv/bin/activate)
pip install -r requirements.txt

# Demo site (Member 1)
cd demo-site
npm install

# Admin panel (Member 2)
cd admin-panel
npm install
```

`node_modules` aur `venv` Git mein push nahi hote. Clone ke baad har banda ye commands khud chalata hai.

## 5. Chalane ke commands (3 terminals)

| Terminal | Folder | Command |
|---|---|---|
| 1 | `backend/` | `uvicorn main:app --host 0.0.0.0 --port 8000` |
| 2 | `demo-site/` | `npm run dev` |
| 3 | `admin-panel/` | `npm run dev` |

## 6. Har member ko kya seekhna hai (zaroorat ke mutabiq)

| Member | Zaroori topics |
|---|---|
| Member 1 | React basics (components, `useState`, `useEffect`), `fetch`, React Router, Python `requests` |
| Member 2 | React basics, `fetch`, React Router, tables aur lists dikhana |
| Member 3 | FastAPI routes, SQLAlchemy models, Pydantic schemas, `argon2-cffi`, `hashlib` |

## 7. Rules (sab ke liye)
1. Sirf **apne folder** mein kaam karo.
2. `.env` aur `*.db` Git par push nahi hongi.
3. API contract (`PROJECT_CONTEXT.md` section 9) badalna ho to pehle group ko batao.
4. Frontend mein security logic mat likho, wo backend ka kaam hai.
5. Sirf test accounts par demo karo.
6. Har banda roz commit aur push kare.
