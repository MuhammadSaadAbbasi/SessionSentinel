# schemas.py
# Request ka format. FastAPI in se check karta hai ke frontend ne sahi fields bheje ya nahi.
from pydantic import BaseModel


class LoginRequest(BaseModel):
    email: str
    password: str
    device_id: str      # browser ka random ID (frontend ek baar banata hai, localStorage mein rakhta hai)


class SignupRequest(BaseModel):
    email: str
    password: str


class TokenRequest(BaseModel):
    token: str


class IncidentStatusRequest(BaseModel):
    status: str
    note: str = ""


class UserReportRequest(BaseModel):
    event_id: int
    is_me: bool


class PasswordResetRequest(BaseModel):
    email: str
    new_password: str


class VerificationRequestBody(BaseModel):
    token: str
