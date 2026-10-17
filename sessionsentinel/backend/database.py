# database.py
# Is file ka kaam: database se connection banana.
# Baqi files (models.py, main.py, seed.py, routers) yahin se connection leti hain.

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

from config import DATABASE_URL    # config.py se database ka address

# engine = database tak pahunchne ka "rasta".
# check_same_thread=False: SQLite ko batata hai ke FastAPI kai threads se use karega.
# (Ye option sirf SQLite ke liye hai.)
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# SessionLocal = ek factory. Isay call karo to database ke saath "baat-cheet" (db session) milta hai.
# NOTE: ye SQLAlchemy ka db session hai. Hamare "login session" (token wale) se alag cheez hai.
# autoflush=False / autocommit=False: hum khud decide karte hain ke data kab save (commit) ho.
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


# Base = sab tables (models) ki "maa" class. Har table class isay inherit karegi.
class Base(DeclarativeBase):
    pass


# get_db: FastAPI ke endpoints ke liye helper.
# Har request par db session khulta hai, kaam hone ke baad (chahe error aaye) band ho jata hai.
# Day 2 mein hum endpoints mein aise likhenge: def login(db = Depends(get_db))
def get_db():
    db = SessionLocal()
    try:
        yield db          # endpoint ko db de do
    finally:
        db.close()        # kaam khatam, connection band
