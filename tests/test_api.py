"""Tests for the FastAPI endpoints."""
import pytest
from pathlib import Path

# Add backend to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Create a test client."""
    # Need to set environment variables before importing
    import os
    os.environ.setdefault("OPENAI_API_KEY", "test-key-not-used-in-tests")
    
    from backend.main import app
    with TestClient(app) as test_client:
        yield test_client


def test_root_endpoint(client):
    """Test the root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "name" in data
    assert "endpoints" in data


def test_health_endpoint(client):
    """Test the health check endpoint."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


def test_list_policies(client):
    """Test listing all policies."""
    response = client.get("/api/v1/policies")
    assert response.status_code == 200
    data = response.json()
    assert "policies" in data
    assert len(data["policies"]) > 0


def test_get_policy(client):
    """Test getting a specific policy."""
    response = client.get("/api/v1/policies/SEC-001")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "SEC-001"
    assert "description" in data


def test_get_policy_not_found(client):
    """Test getting a non-existent policy."""
    response = client.get("/api/v1/policies/NONEXISTENT")
    assert response.status_code == 404


def test_analyze_code_with_violations(client):
    """Test analyzing code with violations."""
    response = client.post("/api/v1/analyze", json={
        "code": "password = 'secret123'",
        "language": "python"
    })
    assert response.status_code == 200
    data = response.json()
    assert "violations" in data
    assert len(data["violations"]) > 0


def test_analyze_clean_code(client):
    """Test analyzing clean code."""
    response = client.post("/api/v1/analyze", json={
        "code": "import os\nvalue = os.environ.get('SECRET')",
        "language": "python"
    })
    assert response.status_code == 200
    data = response.json()
    assert "violations" in data
    # Should have few or no violations
    sec001_violations = [v for v in data["violations"] if v["rule_id"] == "SEC-001"]
    assert len(sec001_violations) == 0


def test_analyze_summary(client):
    """Test analyze summary endpoint."""
    response = client.post("/api/v1/analyze/summary", json={
        "code": "password = 'test'\napi_key = 'secret'",
        "language": "python"
    })
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "by_severity" in data
    assert "violations" in data


def test_adjudicate(client):
    """Test adjudication endpoint."""
    # First analyze to get violations
    analyze_response = client.post("/api/v1/analyze", json={
        "code": "password = 'secret'",
        "language": "python"
    })
    analysis = analyze_response.json()
    
    # Then adjudicate
    response = client.post("/api/v1/adjudicate", json=analysis)
    assert response.status_code == 200
    data = response.json()
    assert "compliant" in data
    assert "reasoning" in data


def test_adjudicate_clean(client):
    """Test adjudication of clean code."""
    analyze_response = client.post("/api/v1/analyze", json={
        "code": "import os\nvalue = os.environ.get('X')",
        "language": "python"
    })
    analysis = analyze_response.json()
    
    response = client.post("/api/v1/adjudicate", json=analysis)
    assert response.status_code == 200
    data = response.json()
    # Clean code should be compliant
    assert data["compliant"] is True


def test_get_fix_guidance(client):
    """Test getting fix guidance."""
    analyze_response = client.post("/api/v1/analyze", json={
        "code": "password = 'secret'\neval(cmd)",
        "language": "python"
    })
    analysis = analyze_response.json()
    
    response = client.post("/api/v1/adjudicate/guidance", json=analysis)
    assert response.status_code == 200
    data = response.json()
    assert "guidance" in data
    assert "violation_count" in data


def test_policies_by_severity(client):
    """Test filtering policies by severity."""
    response = client.get("/api/v1/policies/severity/high")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    for policy in data:
        assert policy["severity"] == "high"


def test_policies_invalid_severity(client):
    """Test invalid severity filter."""
    response = client.get("/api/v1/policies/severity/invalid")
    assert response.status_code == 400


def test_list_test_cases(client):
    """Test listing unified test cases (db + file sources)."""
    response = client.get("/api/v1/test-cases")
    assert response.status_code == 200
    data = response.json()
    assert "cases" in data
    assert isinstance(data["cases"], list)
    assert any(item["source"] == "file" for item in data["cases"])


def test_test_case_crud(client):
    """Test DB-backed test case CRUD lifecycle."""
    create_response = client.post(
        "/api/v1/test-cases",
        json={
            "name": "API CRUD Test Case",
            "description": "created in test",
            "language": "python",
            "code": "print('hello')",
            "tags": ["api", "crud"],
        },
    )
    assert create_response.status_code == 200
    created = create_response.json()
    assert created["source"] == "db"
    case_id = created["id"]

    get_response = client.get(f"/api/v1/test-cases/{case_id}")
    assert get_response.status_code == 200
    fetched = get_response.json()
    assert fetched["code"] == "print('hello')"

    update_response = client.put(
        f"/api/v1/test-cases/{case_id}",
        json={
            "name": "API CRUD Test Case Updated",
            "description": "updated",
            "code": "print('updated')",
        },
    )
    assert update_response.status_code == 200
    updated = update_response.json()
    assert updated["name"] == "API CRUD Test Case Updated"
    assert updated["code"] == "print('updated')"

    delete_response = client.delete(f"/api/v1/test-cases/{case_id}")
    assert delete_response.status_code == 200
    deleted_data = delete_response.json()
    assert deleted_data["success"] is True

    get_deleted_response = client.get(f"/api/v1/test-cases/{case_id}")
    assert get_deleted_response.status_code == 404
