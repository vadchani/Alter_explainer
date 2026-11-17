from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base, get_db
from main import app


ALERT_PAYLOAD = {
    "title": "CPU spike",
    "source": "api-gateway",
    "severity": "CRITICAL",
    "metric_name": "cpu_utilization",
    "metric_value": 96.5,
    "threshold": 85.0,
}


@pytest.fixture
def client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    testing_session = sessionmaker(bind=engine, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        with testing_session() as session:
            yield session

    previous_overrides = app.dependency_overrides.copy()
    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous_overrides)
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_create_alert(client):
    response = client.post("/alerts", json=ALERT_PAYLOAD)

    assert response.status_code == 201
    alert = response.json()
    assert isinstance(alert["id"], int)
    for field, value in ALERT_PAYLOAD.items():
        assert alert[field] == value


def test_list_alerts(client):
    initial_response = client.get("/alerts")
    assert initial_response.status_code == 200
    assert initial_response.json() == []

    first_response = client.post("/alerts", json=ALERT_PAYLOAD)
    second_response = client.post(
        "/alerts",
        json={**ALERT_PAYLOAD, "title": "CPU warning", "severity": "WARNING"},
    )
    assert first_response.status_code == 201
    assert second_response.status_code == 201

    response = client.get("/alerts")
    assert response.status_code == 200
    alerts = response.json()
    assert len(alerts) == 2
    assert {alert["id"] for alert in alerts} == {
        first_response.json()["id"],
        second_response.json()["id"],
    }


def test_get_alert_by_id(client):
    create_response = client.post("/alerts", json=ALERT_PAYLOAD)
    assert create_response.status_code == 201
    created_alert = create_response.json()

    response = client.get(f"/alerts/{created_alert['id']}")
    assert response.status_code == 200
    assert response.json() == created_alert


def test_explain_alert(client):
    create_response = client.post("/alerts", json=ALERT_PAYLOAD)
    assert create_response.status_code == 201
    alert = create_response.json()

    response = client.post(f"/alerts/{alert['id']}/explain")
    assert response.status_code == 200
    explanation = response.json()
    assert explanation["alert_id"] == alert["id"]
    assert isinstance(explanation["explanation"], str)
    assert alert["severity"].casefold() in explanation["explanation"].casefold()
    assert alert["metric_name"] in explanation["explanation"]
    assert isinstance(explanation["generated_at"], str)
    datetime.fromisoformat(explanation["generated_at"])


# --- Edge cases added manually ---
def _create_alert(client: TestClient, **overrides: str | float) -> dict:
    """Create an alert through the API and return its JSON response."""
    payload: dict[str, str | float] = {
        "title": "Test alert",
        "severity": "warning",
        "source": "test-source",
        "metric_name": "test_metric",
        "metric_value": 50.0,
        "threshold": 40.0,
    }
    payload.update(overrides)
    response = client.post("/alerts", json=payload)
    assert response.status_code == 201
    return response.json()


def test_explain_alert_for_nonexistent_id_returns_404(client: TestClient) -> None:
    response = client.post("/alerts/999/explain")

    assert response.status_code == 404
    assert response.json()["detail"] == "Alert not found"


def test_explain_alert_when_metric_is_below_threshold(
    client: TestClient,
) -> None:
    alert = _create_alert(
        client,
        title="Connection pool below minimum",
        severity="warning",
        source="db-pool",
        metric_name="active_connections",
        metric_value=2,
        threshold=10,
    )

    response = client.post(f"/alerts/{alert['id']}/explain")

    assert response.status_code == 200
    assert "fell below its threshold" in response.json()["explanation"]


def test_explain_alert_with_zero_threshold_does_not_crash(
    client: TestClient,
) -> None:
    alert = _create_alert(
        client,
        title="Unexpected traffic on idle endpoint",
        severity="info",
        source="edge-cache",
        metric_name="request_count",
        metric_value=5,
        threshold=0,
    )

    response = client.post(f"/alerts/{alert['id']}/explain")

    assert response.status_code == 200
    assert "threshold of 0.0" in response.json()["explanation"]