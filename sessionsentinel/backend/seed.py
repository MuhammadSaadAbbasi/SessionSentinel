# seed.py
# Ek baar chalao: python seed.py
# Ye database ke tables banata hai aur test users daalta hai (1 admin + 5 normal).
# Dobara chalao to purane users ko dobara nahi banata (safe hai).
# IMPORTANT: ye passwords sirf TEST accounts ke hain, kisi asli account mein kabhi use nahi karne.

from database import Base, engine, SessionLocal
from models import User            # models import karna zaroori hai, tab Base ko tables ka pata chalta hai
from security import hash_password

# (email, password, role)
TEST_USERS = [
    ("sessionsentinelserver@gmail.com", "answerable", "admin"),
    ("ali@test.com",   "Test@12345",  "user"),
    ("sara@test.com",  "Test@12345",  "user"),
    ("ahmed@test.com", "Test@12345",  "user"),
    ("bilal@test.com", "Test@12345",  "user"),
    ("zara@test.com",  "Test@12345",  "user"),
    ("saadrehan315@gmail.com",  "Test@12345",  "user"),
 
]


def main():
    Base.metadata.create_all(bind=engine)     # jo tables nahi bane, bana do
    db = SessionLocal()                       # database se baat-cheet shuru
    try:
        for email, password, role in TEST_USERS:
            exists = db.query(User).filter(User.email == email).first()   # pehle se hai?
            if exists:
                print(f"skip (already exists): {email}")
                continue
            db.add(User(email=email, password_hash=hash_password(password), role=role))
            print(f"created: {email} ({role})")
        db.commit()                           # sab changes ek saath save
    finally:
        db.close()
    print("Done. Test passwords seed.py mein hain.")


# Ye line: file seedha chalayi jaye (python seed.py) tab hi main() chale,
# kisi aur file se import karne par na chale.
if __name__ == "__main__":
    main()
