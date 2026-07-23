import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from main import app
import os

client = TestClient(app)

@pytest.fixture
def mock_env(monkeypatch):
    monkeypatch.setenv("PLATFORM_API_KEY", "test-secret-key")

@pytest.fixture
def mock_db_session():
    with patch("main.get_session") as mock_session:
        mock_db = MagicMock()
        mock_session.return_value.__enter__.return_value = mock_db
        yield mock_db

@pytest.fixture
def mock_celery_task():
    with patch("main.run_scan_pipeline.delay") as mock_task:
        mock_task.return_value.id = "mock-task-123"
        yield mock_task

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert "Security Assessment Platform Backend is running." in response.json()["message"]

def test_scan_endpoint_no_auth(mock_env):
    response = client.post("/scan", json={"target": "scanme.nmap.org"})
    # Should be rejected because no X-API-Key header is provided and PLATFORM_API_KEY is set
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or missing API Key"

def test_scan_endpoint_auth_success(mock_env, mock_db_session, mock_celery_task):
    response = client.post(
        "/scan",
        json={"target": "scanme.nmap.org"},
        headers={"X-API-Key": "test-secret-key"}
    )
    assert response.status_code == 202
    data = response.json()
    assert data["message"] == "Scan started"
    assert data["task_id"] == "mock-task-123"

def test_scan_endpoint_invalid_target_internal(mock_env):
    response = client.post(
        "/scan",
        json={"target": "127.0.0.1"},
        headers={"X-API-Key": "test-secret-key"}
    )
    assert response.status_code == 400
    assert "private IP address" in response.json()["detail"] or "loopback" in response.json()["detail"]

def test_scan_endpoint_invalid_target_command_injection(mock_env):
    response = client.post(
        "/scan",
        json={"target": "example.com; rm -rf /"},
        headers={"X-API-Key": "test-secret-key"}
    )
    assert response.status_code == 400
    assert "Invalid character" in response.json()["detail"]

def test_scan_history_auth_enforced(mock_env):
    response = client.get("/history")
    assert response.status_code == 401

def test_scan_history_auth_success(mock_env, mock_db_session):
    mock_db_session.exec.return_value.all.return_value = []
    
    response = client.get(
        "/history",
        headers={"X-API-Key": "test-secret-key"}
    )
    assert response.status_code == 200
    assert response.json() == []
