# main.py
# App ka entry point. uvicorn isi file ko chalata hai: uvicorn main:app

from fastapi import FastAPI

from database import Base, engine
import models                                      # noqa: F401  (tables register hon, is liye import zaroori)
from routers import auth, me, admin, audit         # chaaron routers (abhi khali, Day 2 se bharenge)

# Server start hote hi tables bana do agar nahi bane (seed.py bhool jaye to bhi chale)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="SessionSentinel")             # asli application object

# Har router ke endpoints ko app se jodo
app.include_router(auth.router)
app.include_router(me.router)
app.include_router(admin.router)
app.include_router(audit.router)


# Sab se pehla endpoint: "server zinda hai?"
# @app.get("/health") ka matlab: browser GET /health kare to ye function chale.
@app.get("/health")
def health():
    return {"status": "ok"}                        # FastAPI ise khud JSON bana deta hai
