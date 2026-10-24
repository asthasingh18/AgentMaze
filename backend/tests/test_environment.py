
from unittest.mock import Mock, patch

from app.agents.agent import Agent
from app.simulation.environment import Environment
from app.tools.tool import Tool


def make_environment():
    environment = Environment()
    agent = Agent("A001", "Agent-A", permissions=["customer_search"])
    tool = Tool("T001", "Customer Search", "customer_search")

    environment.add_agent(agent)
    environment.add_tool(tool)

    return environment, agent, tool


def test_run_tool_returns_error_for_unknown_agent():
    environment, _, _ = make_environment()

    result = environment.run_tool("UNKNOWN", "T001")

    assert result == {
        "success": False,
        "message": "Agent UNKNOWN not found",
    }


def test_run_tool_returns_error_for_unknown_tool():
    environment, _, _ = make_environment()

    result = environment.run_tool("A001", "UNKNOWN")

    assert result == {
        "success": False,
        "message": "Tool UNKNOWN not found",
    }


def test_run_tool_records_unauthorized_tool_access():
    environment, _, _ = make_environment()

    with patch("app.database.agent_has_tool", return_value=False):
        result = environment.run_tool("A001", "T001")

    assert result["success"] is False
    assert "not assigned" in result["message"]
    assert any(
        event.get("event_type") == "MCP_PLUGIN_ABUSE"
        for event in environment.get_attack_events()
    )


def test_run_tool_records_capability_abuse_when_execution_fails():
    environment, agent, tool = make_environment()
    tool.execute = Mock(return_value={
        "success": False,
        "message": "Missing capability",
    })

    with patch("app.database.agent_has_tool", return_value=True):
        result = environment.run_tool("A001", "T001")

    assert result["success"] is False
    assert any(
        event.get("event_type") == "CAPABILITY_ABUSE"
        for event in environment.get_attack_events()
    )


def test_delegate_task_rejects_unknown_agent():
    environment, _, _ = make_environment()

    result = environment.delegate_task(
        "A001", "UNKNOWN", "Search records", "customer_search"
    )

    assert result["success"] is False
    assert result["message"] == "Delegation failed: unknown agent id"


def test_delegate_task_blocks_missing_capability():
    environment = Environment()
    source = Agent("A001", "Agent-A", permissions=["customer_search"])
    target = Agent("A002", "Agent-B", permissions=[])

    environment.add_agent(source)
    environment.add_agent(target)

    result = environment.delegate_task(
        "A001", "A002", "Access database", "database_admin"
    )

    assert result["success"] is False
    assert "lacks required capability" in result["message"]
    assert any(
        event.get("event_type") == "INTER_AGENT_TRUST_ESCALATION"
        for event in environment.get_attack_events()
    )


def test_delegate_task_accepts_boolean_capability_verification():
    environment, source, target = make_environment()
    target.verify_capability = Mock(return_value=True)

    result = environment.delegate_task(
        "A001", "A001", "Search records", "customer_search"
    )

    assert result["success"] is True
    assert result["delegation"]["from_agent"] == source.agent_id
