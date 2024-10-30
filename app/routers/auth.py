from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer
from ..schemas.auth import LoginRequest, TokenResponse, TokenValidationResponse
from ..services.auth_service import AuthService
import os

router = APIRouter(
    prefix="/auth",
    tags=["authentication"]
)

security = HTTPBearer()
auth_service = AuthService(os.getenv("JWT_SECRET_KEY", "secret_key"))

@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest):
    try:
        token = await auth_service.authenticate_user(
            request.username, 
            request.password
        )
        return TokenResponse(access_token=token)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/validate-token", response_model=TokenValidationResponse)
async def validate_token(token: str):
    try:
        user_context = await auth_service.validate_token(token)
        return TokenValidationResponse(**user_context)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")
    
@router.get("/health")
async def health():
    return {"status": "OK"}