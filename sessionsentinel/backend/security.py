# security.py
# Password hashing aur token banane ke helpers.
# Hum apni crypto kabhi nahi banate: established libraries use karte hain.

import secrets                                           # Python ka secure random generator
from argon2 import PasswordHasher                        # Argon2id password hasher
from argon2.exceptions import VerificationError, InvalidHashError

# PasswordHasher() ka default Argon2id hota hai, jo password hashing ke liye recommended hai.
ph = PasswordHasher()


def hash_password(password: str) -> str:
    # Password ko hash mein badalta hai. Har baar alag "salt" lagta hai, is liye
    # same password ke do hash alag aate hain. Database mein sirf ye hash jata hai.
    return ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    # Login ke waqt: diya hua password database ke hash se match karta hai ya nahi?
    # NOTE: argon2 ka verify pehle HASH leta hai, phir PASSWORD.
    try:
        return ph.verify(password_hash, password)        # sahi ho to True return karta hai
    except (VerificationError, InvalidHashError):        # galat password ya kharab hash
        return False                                     # error ke bajaye False, taake login code saaf rahe


def new_token() -> str:
    # Session ka random pass. secrets.token_urlsafe(32) = 32 random bytes, URL mein bhejne layak.
    # Isay guess karna practically namumkin hai. (random module is kaam ke liye use NAHI karte.)
    return secrets.token_urlsafe(32)
