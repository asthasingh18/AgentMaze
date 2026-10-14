
from app.security.attack_event import AttackEvent
from app.security.mitigation_engine import MitigationEngine


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


def test_mitigation_covers_both_branches():
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

    mcp = make_event(
        "MCP_TOOL_ABUSE",
        "TEST-004",
        ["TEST-001"]
    )

    engine = MitigationEngine()

    plan = engine.generate_plan_for_paths([
        [root, context, trust],
        [root, mcp]
    ])

    expected_controls = {
        "GOAL_VALIDATION",
        "MEMORY_PROVENANCE_CHECK",
        "CAPABILITY_VERIFICATION",
        "MCP_PROVENANCE_CHECK"
    }

    assert set(plan["controls"]) == expected_controls
    assert len(plan["actions"]) == 4

    event_types = {
        action["event"]
        for action in plan["actions"]
    }

    assert event_types == {
        "GOAL_HIJACKING",
        "SESSION_CONTEXT_CONTAMINATION",
        "INTER_AGENT_TRUST_ESCALATION",
        "MCP_TOOL_ABUSE"
    }

    print("PASS: Both attack branches have mitigation actions.")
    print("PASS: Shared root event is handled only once.")
    print("MITIGATION BRANCH COVERAGE TEST PASSED")


if __name__ == "__main__":
    test_mitigation_covers_both_branches()
