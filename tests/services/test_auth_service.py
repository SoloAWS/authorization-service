import pytest
from datetime import datetime, timedelta
import httpx
from jose import jwt
import os
from unittest.mock import patch, AsyncMock
from app.services.auth_service import AuthService

# Test constants
TEST_SECRET_KEY = "test_secret_key"
TEST_USER_ID = "test_user_123"
TEST_USERNAME = "test@example.com"
TEST_PASSWORD = "test_password"
TEST_USER_TYPE = "user"

@pytest.fixture
def auth_service():
    return AuthService(TEST_SECRET_KEY)

@pytest.mark.asyncio
async def test_create_access_token_with_default_expiration(auth_service):
    token = auth_service.create_access_token(TEST_USER_ID, TEST_USERNAME, TEST_USER_TYPE)
    
    decoded = jwt.decode(token, TEST_SECRET_KEY, algorithms=["HS256"])
    assert decoded["sub"] == TEST_USER_ID
    assert decoded["username"] == TEST_USERNAME
    assert decoded["user_type"] == TEST_USER_TYPE
    
    # Verify expiration time
    exp_time = datetime.fromtimestamp(decoded["exp"])
    expected_exp = datetime.utcnow() + timedelta(minutes=30)
    assert abs((exp_time - expected_exp).total_seconds()) < 5

@pytest.mark.asyncio
async def test_authenticate_user_success(auth_service):
    mock_response = {
        "id": TEST_USER_ID,
        "user_type": TEST_USER_TYPE
    }
    
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_post.return_value = AsyncMock(
            status_code=200,
            json=lambda: mock_response
        )
        
        token = await auth_service.authenticate_user(TEST_USERNAME, TEST_PASSWORD)
        decoded = jwt.decode(token, TEST_SECRET_KEY, algorithms=["HS256"])
        
        assert decoded["sub"] == TEST_USER_ID
        assert decoded["username"] == TEST_USERNAME
        mock_post.assert_called_once()

@pytest.mark.asyncio
async def test_authenticate_user_invalid_credentials(auth_service):
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_post.return_value = AsyncMock(status_code=401)
        
        with pytest.raises(ValueError, match="Invalid credentials"):
            await auth_service.authenticate_user(TEST_USERNAME, TEST_PASSWORD)

@pytest.mark.asyncio
async def test_authenticate_user_service_unavailable(auth_service):
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_post.side_effect = httpx.RequestError("Connection error")
        
        with pytest.raises(ValueError, match="User service unavailable"):
            await auth_service.authenticate_user(TEST_USERNAME, TEST_PASSWORD)

@pytest.mark.asyncio
async def test_validate_token_success(auth_service):
    token = auth_service.create_access_token(TEST_USER_ID, TEST_USERNAME, TEST_USER_TYPE)
    mock_user_data = {"name": "Test User", "email": TEST_USERNAME}
    
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value = AsyncMock(
            status_code=200,
            json=lambda: mock_user_data
        )
        
        result = await auth_service.validate_token(token)
        
        assert result["user_id"] == TEST_USER_ID
        assert result["username"] == TEST_USERNAME
        assert result["user_type"] == TEST_USER_TYPE
        assert result["user_data"] == mock_user_data

@pytest.mark.asyncio
async def test_validate_token_expired(auth_service):
    # Create an expired token
    exp = datetime.utcnow() - timedelta(minutes=1)
    token = jwt.encode(
        {
            "sub": TEST_USER_ID,
            "username": TEST_USERNAME,
            "user_type": TEST_USER_TYPE,
            "exp": exp
        },
        TEST_SECRET_KEY,
        algorithm="HS256"
    )
    
    with pytest.raises(ValueError, match="Invalid token"):
        await auth_service.validate_token(token)

@pytest.mark.asyncio
async def test_validate_token_invalid_signature(auth_service):
    token = jwt.encode(
        {
            "sub": TEST_USER_ID,
            "username": TEST_USERNAME,
            "user_type": TEST_USER_TYPE
        },
        "wrong_secret_key",
        algorithm="HS256"
    )
    
    with pytest.raises(ValueError, match="Invalid token"):
        await auth_service.validate_token(token)

@pytest.mark.asyncio
async def test_validate_token_user_not_found(auth_service):
    token = auth_service.create_access_token(TEST_USER_ID, TEST_USERNAME, TEST_USER_TYPE)
    
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.return_value = AsyncMock(status_code=404)
        
        with pytest.raises(ValueError, match="User not found"):
            await auth_service.validate_token(token)

@pytest.mark.asyncio
async def test_validate_token_service_error(auth_service):
    token = auth_service.create_access_token(TEST_USER_ID, TEST_USERNAME, TEST_USER_TYPE)
    
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_get.side_effect = httpx.RequestError("Service error")
        
        with pytest.raises(ValueError, match="Invalid token"):
            await auth_service.validate_token(token)

@pytest.mark.asyncio
async def test_auth_service_initialization():
    # Test with environment variable
    with patch.dict(os.environ, {'USER_SERVICE_URL': 'http://test-service:8000'}):
        service = AuthService(TEST_SECRET_KEY)
        assert service.user_service_url == 'http://test-service:8000/user'
    
    # Test with default value
    with patch.dict(os.environ, clear=True):
        service = AuthService(TEST_SECRET_KEY)
        assert service.user_service_url == 'http://localhost:8002/user'

@pytest.mark.asyncio
async def test_validate_token_malformed(auth_service):
    with pytest.raises(ValueError, match="Invalid token"):
        await auth_service.validate_token("malformed.token.here")

@pytest.mark.asyncio
async def test_authenticate_user_unexpected_response(auth_service):
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_post.return_value = AsyncMock(
            status_code=200,
            json=lambda: {"unexpected": "response"}
        )
        
        with pytest.raises(KeyError):
            await auth_service.authenticate_user(TEST_USERNAME, TEST_PASSWORD)

@pytest.mark.asyncio
async def test_validate_token_missing_claims(auth_service):
    # Create token without required claims
    token = jwt.encode(
        {"some": "data"},
        TEST_SECRET_KEY,
        algorithm="HS256"
    )
    
    with pytest.raises(ValueError, match="Invalid token"):
        await auth_service.validate_token(token)