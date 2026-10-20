# config.py
# Ye file project ki saari settings ek jagah rakhti hai.
# Rule: thresholds (8 fails, 2 minute...) code mein idhar-udhar hardcode nahi karte,
# yahin rakhte hain, taake testing ke dauran sirf yahan badalna paray.

import os                          # os.getenv se environment variables parhne ke liye
from pathlib import Path
from dotenv import load_dotenv     # .env file parhne wala package (python-dotenv)

load_dotenv(Path(__file__).with_name(".env"))

# Database ka address. "sqlite:///./sessionsentinel.db" ka matlab:
# SQLite database, jo current folder mein ek file ban kar rahegi.
# Agar .env mein DATABASE_URL likha ho to wo use hoga, warna ye default.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sessionsentinel.db")

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

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_EMAIL = os.getenv("SMTP_EMAIL", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")
SMTP_TIMEOUT_SECONDS = int(os.getenv("SMTP_TIMEOUT_SECONDS", "8"))
VERIFICATION_TTL_SECONDS = int(os.getenv("VERIFICATION_TTL_SECONDS", str(15 * 60)))
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000")
