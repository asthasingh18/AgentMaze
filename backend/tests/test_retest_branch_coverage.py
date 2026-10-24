
from app.security.attack_event import AttackEvent
from app.security.retest_engine import RetestEngine


def make_event(event_type, event_id, parent_ids=None):
    event = AttackEvent(
        event_type=event_type,
        agent_id="A001",
        description=f"Test event: {event_type}",
        severity="HIGH",
        parent_event_ids=parent_ids or [],
        relation="ENABLES" if parent_ids else None
    )
    event.event_id = event_id
    return event


def test_goal_validation_blocks_root():
    root = make_event("GOAL_HIJACKING", "TEST-001")
    context = make_event(
        "SESSION_CONTEXT_CONTAMINATION",
        "TEST-002",
        ["TEST-001"]
    )
    trust = make_event(
        "INTER_AGENT_TRUST_ESCALATION",
        "TEST-003",
        ["TEST-002"]
    )

    engine = RetestEngine()
    engine.blocked_controls.add("GOAL_VALIDATION")

    result = engine.retest_path([root, context, trust])

    assert result["status"] == "PASS"
    assert result["blocked_at"] == "GOAL_HIJACKING"
    assert result["blocked_control"] == "GOAL_VALIDATION"
    assert result["executed_steps"] == []

    print("PASS: Goal validation blocks the path at its root.")


def test_mcp_control_blocks_tool_abuse():
    root = make_event("MCP_TOOL_ABUSE", "TEST-004")

    engine = RetestEngine()
    engine.blocked_controls.add("MCP_PROVENANCE_CHECK")

    result = engine.retest_path([root])

    assert result["status"] == "PASS"
    assert result["blocked_at"] == "MCP_TOOL_ABUSE"
    assert result["blocked_control"] == "MCP_PROVENANCE_CHECK"
    assert result["executed_steps"] == []

    print("PASS: MCP provenance control blocks tool abuse.")


def test_missing_control_leaves_path_exploitable():
    root = make_event("MCP_TOOL_ABUSE", "TEST-005")

    engine = RetestEngine()

    result = engine.retest_path([root])

    assert result["status"] == "FAIL"
    assert result["blocked_at"] is None
    assert len(result["executed_steps"]) == 1

    print("PASS: Missing mitigation leaves the path exploitable.")


if __name__ == "__main__":
    test_goal_validation_blocks_root()
    test_mcp_control_blocks_tool_abuse()
    test_missing_control_leaves_path_exploitable()
    print("RETEST BRANCH COVERAGE TESTS PASSED")
