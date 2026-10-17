# config.py
# Ye file project ki saari settings ek jagah rakhti hai.
# Rule: thresholds (8 fails, 2 minute...) code mein idhar-udhar hardcode nahi karte,
# yahin rakhte hain, taake testing ke dauran sirf yahan badalna paray.

import os                          # os.getenv se environment variables parhne ke liye
from dotenv import load_dotenv     # .env file parhne wala package (python-dotenv)

load_dotenv()                      # backend/.env file ko load karo (file na ho to bhi error nahi)

# Database ka address. "sqlite:///./sessionsentinel.db" ka matlab:
# SQLite database, jo current folder mein ek file ban kar rahegi.
# Agar .env mein DATABASE_URL likha ho to wo use hoga, warna ye default.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sessionsentinel.db")

# Session token kitne ghante tak valid rahe ga (Day 2 mein login isay use karega)
SESSION_HOURS = int(os.getenv("SESSION_HOURS", "8"))

# --- Detection thresholds (Day 3 mein detection.py inhe use karega) ---
R1_MAX_FAILS = 8            # Rule R1: itne failed logins...
R1_WINDOW_SECONDS = 120     # ...itne seconds (2 minute) ke andar
R1_THROTTLE_SECONDS = 15 * 60
