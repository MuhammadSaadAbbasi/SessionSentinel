# config.py
# Ye file project ki saari settings ek jagah rakhti hai.
# Rule: thresholds (8 fails, 2 minute...) code mein idhar-udhar hardcode nahi karte,
# yahin rakhte hain, taake testing ke dauran sirf yahan badalna paray.

import os                          # os.getenv se environment variables parhne ke liye
from pathlib import Path
from dotenv import load_dotenv     # .env file parhne wala package (python-dotenv)

load_dotenv(Path(__file__).with_name(".env"))

# Database connection URL. Render provides a PostgreSQL URL through DATABASE_URL.
# SQLite remains the local fallback when no environment variable is set.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sessionsentinel.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgresql://", "postgresql+psycopg://", 1
    )

# Session token kitne ghante tak valid rahe ga (Day 2 mein login isay use karega)
SESSION_HOURS = int(os.getenv("SESSION_HOURS", "8"))

# --- Detection and response thresholds ---
R1_HIGH_FAILS = int(os.getenv("R1_HIGH_FAILS", "5"))
R1_CRITICAL_FAILS = int(os.getenv("R1_CRITICAL_FAILS", "10"))
R1_WINDOW_SECONDS = int(os.getenv("R1_WINDOW_SECONDS", "120"))
R1_CORRELATION_SECONDS = int(
    os.getenv("R1_CORRELATION_SECONDS", str(R1_WINDOW_SECONDS))
)
R1_LOCK_SECONDS = int(os.getenv("R1_LOCK_SECONDS", str(30 * 60)))
R6_ACCOUNT_THRESHOLD = int(os.getenv("R6_ACCOUNT_THRESHOLD", "3"))
R6_IP_THROTTLE_SECONDS = int(os.getenv("R6_IP_THROTTLE_SECONDS", str(15 * 60)))

MAILJET_API_KEY = os.getenv("MAILJET_API_KEY", "")
MAILJET_API_SECRET = os.getenv("MAILJET_API_SECRET", "")
MAILJET_FROM_EMAIL = os.getenv("MAILJET_FROM_EMAIL", "")
MAILJET_FROM_NAME = os.getenv("MAILJET_FROM_NAME", "SessionSentinel")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")
VERIFICATION_TTL_SECONDS = int(os.getenv("VERIFICATION_TTL_SECONDS", str(15 * 60)))
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:5173").rstrip("/")
FRONTEND_ORIGINS = [
    origin.strip()
    for origin in os.getenv("FRONTEND_ORIGINS", APP_BASE_URL).split(",")
    if origin.strip()
]
EMAIL_VERIFICATION_TTL_SECONDS = int(
    os.getenv("EMAIL_VERIFICATION_TTL_SECONDS", str(24 * 60 * 60))
)
SESSION_CANCELLATION_TTL_SECONDS = int(
    os.getenv("SESSION_CANCELLATION_TTL_SECONDS", str(30 * 60))
)
