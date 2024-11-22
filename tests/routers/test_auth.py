import pytest
from fastapi.testclient import TestClient
import jwt
from unittest.mock import AsyncMock, patch
from datetime import datetime, timedelta

from app.main import app
from app.services.auth_service import AuthService

# Constants for testing
TEST_SECRET_KEY = "test_secret_key"
TEST_USERNAME = "test@example.com"
TEST_PASSWORD = "test_password"
TEST_USER_ID = "123"
TEST_USER_TYPE = "user"

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def mock_auth_service():
    with patch("app.routers.auth.auth_service") as mock:
        mock.secret_key = TEST_SECRET_KEY
        yield mock

def create_test_token(user_id: str = TEST_USER_ID, username: str = TEST_USERNAME, 
                     user_type: str = TEST_USER_TYPE, expired: bool = False) -> str:
    expire = datetime.utcnow() + timedelta(minutes=-30 if expired else 30)
    data = {
        "sub": user_id,
        "username": username,
        "user_type": user_type,
        "exp": expire
    }
    return jwt.encode(data, TEST_SECRET_KEY, algorithm="HS256")

async def mock_authenticate_success(*args, **kwargs):
    return create_test_token()

async def mock_authenticate_failure(*args, **kwargs):
    raise ValueError("Invalid credentials")

async def mock_validate_token_success(*args, **kwargs):
    return {
        "user_id": TEST_USER_ID,
        "username": TEST_USERNAME,
        "user_type": TEST_USER_TYPE,
        "user_data": {"name": "Test User"}
    }

async def mock_validate_token_failure(*args, **kwargs):
    raise ValueError("Invalid token")

def test_login_success(client, mock_auth_service):
    mock_auth_service.authenticate_user = AsyncMock(side_effect=mock_authenticate_success)
    
    response = client.post(
        "/auth/login",
        json={"username": TEST_USERNAME, "password": TEST_PASSWORD}
    )
    
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["access_token"] == create_test_token()
    mock_auth_service.authenticate_user.assert_called_once_with(TEST_USERNAME, TEST_PASSWORD)

def test_login_invalid_credentials(client, mock_auth_service):
    mock_auth_service.authenticate_user = AsyncMock(side_effect=mock_authenticate_failure)
    
    response = client.post(
        "/auth/login",
        json={"username": TEST_USERNAME, "password": "wrong_password"}
    )
    
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"

def test_login_invalid_request_body(client):
    response = client.post(
        "/auth/login",
        json={"username": TEST_USERNAME}  # Missing password
    )
    
    assert response.status_code == 400

def test_validate_token_success(client, mock_auth_service):
    mock_auth_service.validate_token = AsyncMock(side_effect=mock_validate_token_success)
    test_token = create_test_token()
    
    response = client.post(
        f"/auth/validate-token?token={test_token}"
    )
    print(response.json())
    assert response.status_code == 200
    assert response.json() == {
        "user_id": TEST_USER_ID,
        "username": TEST_USERNAME,
        "user_type": TEST_USER_TYPE,
        "user_data": {"name": "Test User"}
    }
    mock_auth_service.validate_token.assert_called_once_with(test_token)

def test_validate_token_invalid(client, mock_auth_service):
    mock_auth_service.validate_token = AsyncMock(side_effect=mock_validate_token_failure)
    
    response = client.post(
        "/auth/validate-token?token=invalid_token"
    )
    
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid token"

def test_validate_token_missing(client):
    response = client.post(
        "/auth/validate-token",
        json={}
    )
    
    assert response.status_code == 400

def test_health_check(client):
    response = client.get("/auth/health")
    
    assert response.status_code == 200
    assert response.json() == {"status": "OK"}

@pytest.mark.asyncio
async def test_auth_service_create_token():
    auth_service = AuthService(TEST_SECRET_KEY)
    token = auth_service.create_access_token(TEST_USER_ID, TEST_USERNAME, TEST_USER_TYPE)
    
    decoded = jwt.decode(token, TEST_SECRET_KEY, algorithms=["HS256"])
    assert decoded["sub"] == TEST_USER_ID
    assert decoded["username"] == TEST_USERNAME
    assert decoded["user_type"] == TEST_USER_TYPE
    assert "exp" in decoded

@pytest.mark.asyncio
async def test_auth_service_validate_valid_token():
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {"name": "Test User"}
        
        auth_service = AuthService(TEST_SECRET_KEY)
        token = create_test_token()
        result = await auth_service.validate_token(token)
        
        assert result["user_id"] == TEST_USER_ID
        assert result["username"] == TEST_USERNAME
        assert result["user_type"] == TEST_USER_TYPE
        assert "user_data" in result

@pytest.mark.asyncio
async def test_auth_service_validate_expired_token():
    auth_service = AuthService(TEST_SECRET_KEY)
    expired_token = create_test_token(expired=True)
    
    with pytest.raises(ValueError, match="Invalid token"):
        await auth_service.validate_token(expired_token)

@pytest.mark.asyncio
async def test_auth_service_authenticate_user_success():
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            "id": TEST_USER_ID,
            "user_type": TEST_USER_TYPE
        }
        
        auth_service = AuthService(TEST_SECRET_KEY)
        token = await auth_service.authenticate_user(TEST_USERNAME, TEST_PASSWORD)
        
        decoded = jwt.decode(token, TEST_SECRET_KEY, algorithms=["HS256"])
        assert decoded["sub"] == TEST_USER_ID
        assert decoded["username"] == TEST_USERNAME
        assert decoded["user_type"] == TEST_USER_TYPE

@pytest.mark.asyncio
async def test_auth_service_authenticate_user_failure():
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_post.return_value.status_code = 401
        
        auth_service = AuthService(TEST_SECRET_KEY)
        with pytest.raises(ValueError, match="Invalid credentials"):
            await auth_service.authenticate_user(TEST_USERNAME, "wrong_password")