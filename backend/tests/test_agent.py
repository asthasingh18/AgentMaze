
from unittest.mock import patch

from app.agents.agent import Agent


def test_can_use_checks_database_capabilities():
    agent = Agent("A001", "Test Agent")

    with patch(
        "app.agents.agent.get_agent_capabilities",
        return_value=["customer_search", "read_records"],
    ) as mock_get_capabilities:
        assert agent.can_use("customer_search") is True
        assert agent.can_use("database_admin") is False

    mock_get_capabilities.assert_called_with("A001")


def test_get_memory_returns_stored_memory():
    agent = Agent("A001", "Test Agent")

    agent.remember(
        content="Verify permissions",
        source="security_test",
        trust_level="HIGH",
    )

    result = agent.get_memory()

    assert len(result) == 1
    assert result[0]["content"] == "Verify permissions"
    assert result[0]["source"] == "security_test"
    assert result[0]["trust_level"] == "HIGH"


def test_agent_string_representation():
    agent = Agent("A001", "Test Agent")

    assert str(agent) == "Test Agent (A001)"
