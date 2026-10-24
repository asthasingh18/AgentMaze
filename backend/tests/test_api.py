
from fastapi.testclient import TestClient

from app.api import app


client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["project"] == "AgentMaze"


def test_attack_events_endpoint():
    response = client.get("/api/attack-events")

    assert response.status_code == 200

    data = response.json()
    assert "total" in data
    assert "events" in data
    assert isinstance(data["events"], list)
    assert data["total"] == len(data["events"])


def test_attack_paths_endpoint():
    response = client.get("/api/attack-paths")

    assert response.status_code == 200

    data = response.json()
    assert "total" in data
    assert "attack_paths" in data
    assert isinstance(data["attack_paths"], list)
    assert data["total"] == len(data["attack_paths"])


def test_simulate_endpoint():
    response = client.post("/api/simulate")

    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "completed"
    assert "results" in data
    assert data["results"]["authorized_delegation"]["success"] is True
    assert data["results"]["unauthorized_delegation"]["success"] is False


def test_resilience_analysis_endpoint():
    response = client.post("/api/resilience-analysis")

    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "completed"
    assert data["metrics"]["total_operations"] == 2
    assert data["metrics"]["successful_operations"] == 1
    assert data["metrics"]["security_blocks"] == 1
    assert data["metrics"]["unexpected_successes"] == 0
    assert data["metrics"]["safe_outcome_rate_percent"] == 100.0

def test_invalid_endpoint():
    response = client.get("/api/invalid-endpoint")

    assert response.status_code == 404
    assert response.json()["detail"] == "Not Found"

from unittest.mock import MagicMock, patch


def test_simulate_endpoint_rolls_back_when_database_insert_fails():
    mock_connection = MagicMock()
    mock_cursor = mock_connection.cursor.return_value
    mock_cursor.execute.side_effect = RuntimeError("Database insert failed")

    with patch("app.api.sqlite3.connect", return_value=mock_connection):
        with patch(
            "app.api.uuid4"
        ) as mock_uuid:
            mock_uuid.return_value.hex = "12345678abcdef"
            try:
                client.post("/api/simulate")
                assert False, "Expected the database error to be raised"
            except RuntimeError as error:
                assert str(error) == "Database insert failed"

    mock_connection.rollback.assert_called_once()
    mock_connection.close.assert_called_once()


def test_resilience_analysis_rolls_back_when_database_insert_fails():
    mock_connection = MagicMock()
    mock_cursor = mock_connection.cursor.return_value
    mock_cursor.execute.side_effect = RuntimeError("Database insert failed")

    with patch("app.api.sqlite3.connect", return_value=mock_connection):
        try:
            client.post("/api/resilience-analysis")
            assert False, "Expected the database error to be raised"
        except RuntimeError as error:
            assert str(error) == "Database insert failed"

    mock_connection.rollback.assert_called_once()
    mock_connection.close.assert_called_once()

