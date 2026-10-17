# schemas.py
# Request ka format. FastAPI in se check karta hai ke frontend ne sahi fields bheje ya nahi.
from pydantic import BaseModel


class LoginRequest(BaseModel):
    email: str
    password: str
    device_id: str      # browser ka random ID (frontend ek baar banata hai, localStorage mein rakhta hai)
