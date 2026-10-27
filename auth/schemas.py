from pydantic import BaseModel, EmailStr
from typing import Optional

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class AuthenticationResponse(BaseModel):
    accesstoken: str
    tokentype: str="brearer"
    uid: str
    email: str
    role: str
    message: str