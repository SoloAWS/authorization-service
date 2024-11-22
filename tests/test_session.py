import pytest
import os
from sqlalchemy.orm import Session
from app.session import SessionConfig, get_db, engine

def test_session_config_with_env_vars(monkeypatch):
    # Setup environment variables
    env_vars = {
        'DB_USERNAME': 'test_user',
        'DB_PASSWORD': 'test_pass',
        'DB_HOST': 'test_host',
        'DB_NAME': 'test_db',
        'DB_PORT': '5432'
    }
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)
    
    config = SessionConfig()
    url = config.url()
    
    assert url == 'postgresql://test_user:test_pass@test_host:5432/test_db'

def test_session_config_without_env_vars(monkeypatch):
    # Remove environment variables
    for var in ['DB_USERNAME', 'DB_PASSWORD', 'DB_HOST', 'DB_NAME', 'DB_PORT']:
        monkeypatch.delenv(var, raising=False)
    
    config = SessionConfig()
    url = config.url()
    
    assert url == 'sqlite:///./test.db'

def test_session_config_partial_env_vars(monkeypatch):
    # Set only some environment variables
    monkeypatch.setenv('DB_USERNAME', 'test_user')
    monkeypatch.setenv('DB_PASSWORD', 'test_pass')
    # Missing other variables
    
    config = SessionConfig()
    url = config.url()
    
    assert url == 'sqlite:///./test.db'

def test_get_db():
    db = next(get_db())
    assert isinstance(db, Session)
    db.close()

def test_engine_configuration():
    assert engine is not None
    assert engine.url is not None