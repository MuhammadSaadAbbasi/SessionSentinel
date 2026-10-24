# main.py
# App ka entry point. uvicorn isi file ko chalata hai: uvicorn main:app

from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI
from sqlalchemy import inspect, text

from database import Base, engine
from config import FRONTEND_ORIGINS
import models                                      # noqa: F401  (tables register hon, is liye import zaroori)
from routers import auth, me, admin, audit         # chaaron routers (abhi khali, Day 2 se bharenge)

# Server start hote hi tables bana do agar nahi bane (seed.py bhool jaye to bhi chale)
Base.metadata.create_all(bind=engine)
if "users" in inspect(engine).get_table_names():
    columns = {column["name"] for column in inspect(engine).get_columns("users")}
    if "password_reset_required" not in columns:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE users ADD COLUMN password_reset_required "
                    "BOOLEAN NOT NULL DEFAULT 0"
                )
            )
    if "email_verified" not in columns:
        with engine.begin() as connection:
            connection.execute(text(
                "ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT 1"
            ))
    if "email_verified_at" not in columns:
        with engine.begin() as connection:
            connection.execute(
                text("ALTER TABLE users ADD COLUMN email_verified_at TIMESTAMP")
            )
    if "status" not in columns:
        with engine.begin() as connection:
            connection.execute(
                text("ALTER TABLE users ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'active'")
            )

app = FastAPI(title="SessionSentinel")             # asli application object
app.add_middleware(
    CORSMiddleware,
    allow_origins=FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
