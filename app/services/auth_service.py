# app/services/auth_service.py
from jose import JWTError, jwt
from typing import Dict
from datetime import datetime, timedelta
import httpx
import os

class AuthService:
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.user_service_url = os.getenv("USER_SERVICE_URL", "http://localhost:8002/user")
        self.algorithm = "HS256"
        self.access_token_expire_minutes = 30

    def create_access_token(self, user_id: str, username: str, user_type: str) -> str:
        expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        to_encode = {
            "sub": user_id,
            "username": username,
            "user_type": user_type,
            "exp": expire
        }
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)

    async def authenticate_user(self, username: str, password: str) -> str:
        # Call user service to validate credentials
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    f"{self.user_service_url}/user/validate-credentials",
                    json={"username": username, "password": password}
                )
                if response.status_code == 200:
                    user_data = response.json()
                    return self.create_access_token(
                        user_id=str(user_data["id"]),
                        username=username,
                        user_type=user_data.get("user_type", "user")
                    )
            except httpx.RequestError:
                raise ValueError("User service unavailable")
        raise ValueError("Invalid credentials")

    async def validate_token(self, token: str) -> Dict:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            # Get user details from user service
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self.user_service_url}/user/{payload['sub']}"
                )
                if response.status_code == 200:
                    user_data = response.json()
                    return {
                        "user_id": payload["sub"],
                        "username": payload["username"],
                        "user_type": payload["user_type"],
                        "user_data": user_data
                    }
                raise ValueError("User not found")
        except JWTError:
            raise ValueError("Invalid token")
