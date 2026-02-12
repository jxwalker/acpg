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


def test_runtime_policies_list_and_evaluate(client):
    """Runtime policy endpoints should list and evaluate deterministic decisions."""
    list_response = client.get("/api/v1/runtime/policies")
    assert list_response.status_code == 200
    listed = list_response.json()
    assert "rules" in listed
    assert "count" in listed

    eval_response = client.post(
        "/api/v1/runtime/policies/evaluate",
        json={
            "event_type": "tool",
            "tool_name": "pip",
            "command": ["pip", "install", "requests"],
            "language": "python",
        },
    )
    assert eval_response.status_code == 200
    evaluated = eval_response.json()
    assert evaluated["decision"]["action"] in {
        "allow",
        "deny",
        "require_approval",
        "allow_with_monitoring",
    }


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


def test_dynamic_artifact_history_index(client):
    """Dynamic artifact index should expose replay metadata for audit flows."""
    from app.core.config import settings

    original_dynamic = settings.ENABLE_DYNAMIC_TESTING
    original_static = settings.ENABLE_STATIC_ANALYSIS
    original_timeout = settings.DYNAMIC_SANDBOX_TIMEOUT_SECONDS
    try:
        settings.ENABLE_DYNAMIC_TESTING = True
        settings.ENABLE_STATIC_ANALYSIS = False
        settings.DYNAMIC_SANDBOX_TIMEOUT_SECONDS = 2
        client.delete("/api/v1/history")

        response = client.post(
            "/api/v1/analyze",
            json={
                "code": "def main():\n    raise RuntimeError('history-dynamic')\n\nmain()\n",
                "language": "python",
            },
        )
        assert response.status_code == 200
        analysis = response.json()
        assert analysis.get("dynamic_analysis", {}).get("executed") is True

        index_response = client.get("/api/v1/history/dynamic-artifacts?violations_only=true")
        assert index_response.status_code == 200
        payload = index_response.json()
        assert payload["total"] >= 1
        assert any(item["suite_id"] == "direct_execution" for item in payload["artifacts"])
        assert all(item.get("replay_fingerprint") for item in payload["artifacts"])

        filtered_response = client.get(
            "/api/v1/history/dynamic-artifacts?suite_id=direct_execution&language=python&violations_only=true"
        )
        assert filtered_response.status_code == 200
        filtered_payload = filtered_response.json()
        assert filtered_payload["total"] >= 1
        assert all(item["suite_id"] == "direct_execution" for item in filtered_payload["artifacts"])
        assert all(item["language"] == "python" for item in filtered_payload["artifacts"])
    finally:
        settings.ENABLE_DYNAMIC_TESTING = original_dynamic
        settings.ENABLE_STATIC_ANALYSIS = original_static
        settings.DYNAMIC_SANDBOX_TIMEOUT_SECONDS = original_timeout
        client.delete("/api/v1/history")


def test_history_trends_endpoint(client):
    """History trends should aggregate compliance and rule statistics."""
    client.delete("/api/v1/history")
    try:
        response_bad = client.post(
            "/api/v1/analyze",
            json={"code": "password = 'trend-secret'", "language": "python"},
        )
        assert response_bad.status_code == 200

        response_good = client.post(
            "/api/v1/analyze",
            json={"code": "import os\nvalue = os.environ.get('SECRET')", "language": "python"},
        )
        assert response_good.status_code == 200

        trends_response = client.get("/api/v1/history/trends?days=30")
        assert trends_response.status_code == 200
        trends = trends_response.json()

        assert trends["window_days"] == 30
        assert trends["total_runs"] >= 2
        assert 0 <= trends["compliance_rate"] <= 100
        assert isinstance(trends["series"], list)
        assert len(trends["series"]) >= 1
        assert isinstance(trends["top_violated_rules"], list)
        if trends["top_violated_rules"]:
            assert "rule_id" in trends["top_violated_rules"][0]
            assert "count" in trends["top_violated_rules"][0]
    finally:
        client.delete("/api/v1/history")


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
    response = client.post("/api/v1/adjudicate?solver_mode=skeptical", json=analysis)
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


def test_test_case_bulk_import_export_and_tag_filters(client):
    """Bulk import/export endpoints should support tagging and filtered listing."""
    import_response = client.post(
        "/api/v1/test-cases/import",
        json={
            "overwrite": False,
            "match_by": "name_language",
            "cases": [
                {
                    "name": "Bulk Case Finance",
                    "description": "finance compliance sample",
                    "language": "python",
                    "code": "print('finance')",
                    "tags": ["finance", "regression"],
                },
                {
                    "name": "Bulk Case Pharma",
                    "description": "pharma compliance sample",
                    "language": "python",
                    "code": "print('pharma')",
                    "tags": ["pharma", "regression"],
                },
            ],
        },
    )
    assert import_response.status_code == 200
    imported = import_response.json()
    assert imported["summary"]["created"] == 2
    created_ids = imported["created_ids"]

    try:
        tags_response = client.get("/api/v1/test-cases/tags?source=db")
        assert tags_response.status_code == 200
        tags_payload = tags_response.json()
        tags = {item["tag"]: item["count"] for item in tags_payload["tags"]}
        assert "finance" in tags
        assert "pharma" in tags
        assert "regression" in tags

        filtered_response = client.get("/api/v1/test-cases?source=db&tag=finance")
        assert filtered_response.status_code == 200
        filtered_cases = filtered_response.json()["cases"]
        assert any(case["name"] == "Bulk Case Finance" for case in filtered_cases)
        assert all("finance" in case["tags"] for case in filtered_cases)

        export_response = client.get("/api/v1/test-cases/export")
        assert export_response.status_code == 200
        exported = export_response.json()
        assert exported["count"] >= 2
        exported_names = {case["name"] for case in exported["cases"]}
        assert "Bulk Case Finance" in exported_names
        assert "Bulk Case Pharma" in exported_names
    finally:
        for case_id in created_ids:
            client.delete(f"/api/v1/test-cases/{case_id}")


def test_policy_history_and_diff(client):
    """Policy history endpoints should provide version timeline and diffs."""
    import uuid

    policy_id = f"HIST-{uuid.uuid4().hex[:6].upper()}"
    create_payload = {
        "id": policy_id,
        "description": "History test policy",
        "type": "strict",
        "severity": "medium",
        "check": {
            "type": "regex",
            "pattern": "password\\s*=\\s*['\\\"].+['\\\"]",
            "languages": ["python"],
        },
        "fix_suggestion": "Use environment variables",
    }
    update_payload = {
        **create_payload,
        "description": "History test policy updated",
        "severity": "high",
        "fix_suggestion": "Use a secret manager",
    }

    create_response = client.post("/api/v1/policies/", json=create_payload)
    assert create_response.status_code == 200

    update_response = client.put(f"/api/v1/policies/{policy_id}", json=update_payload)
    assert update_response.status_code == 200

    history_response = client.get(f"/api/v1/policies/{policy_id}/audit/history")
    assert history_response.status_code == 200
    history = history_response.json()
    assert history["count"] >= 2
    versions = [entry["version"] for entry in history["entries"]]
    assert 1 in versions and 2 in versions

    diff_response = client.get(f"/api/v1/policies/{policy_id}/audit/diff?from_version=1&to_version=2")
    assert diff_response.status_code == 200
    diff = diff_response.json()
    assert diff["policy_id"] == policy_id
    assert "description" in diff["changed_fields"] or "severity" in diff["changed_fields"]

    list_response = client.get("/api/v1/policies/audit/history")
    assert list_response.status_code == 200
    list_data = list_response.json()
    assert isinstance(list_data.get("entries"), list)

    delete_response = client.delete(f"/api/v1/policies/{policy_id}")
    assert delete_response.status_code == 200


def test_policy_group_rollout_preview(client):
    """Rollout preview should evaluate proposed group states against test cases."""
    create_case = client.post(
        "/api/v1/test-cases",
        json={
            "name": "Rollout Preview Case",
            "description": "policy rollout preview test",
            "language": "python",
            "code": "password = 'preview-secret'",
            "tags": ["rollout", "preview"],
        },
    )
    assert create_case.status_code == 200
    case_id = create_case.json()["id"]

    preview = client.post(
        "/api/v1/policies/groups/rollout/preview",
        json={"limit_cases": 5, "semantics": "auto", "solver_decision_mode": "auto"},
    )
    assert preview.status_code == 200
    payload = preview.json()
    assert "baseline" in payload and "proposed" in payload
    assert "cases" in payload
    assert "summary" in payload

    delete_case = client.delete(f"/api/v1/test-cases/{case_id}")
    assert delete_case.status_code == 200
