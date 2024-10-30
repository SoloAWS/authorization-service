from pydantic import BaseModel
from typing import Dict

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str

class TokenValidationResponse(BaseModel):
    user_id: str
    username: str
    user_type: str
    user_data: Dict