
from app.security.security_report import SecurityReport
from app.security.attack_event import AttackEvent


def create_event(event_id, event_type, parent_event_ids=None):
    event = AttackEvent(
        event_type=event_type,
        agent_id="A001",
        description=f"Test event: {event_type}",
        severity="HIGH",
        parent_event_ids=parent_event_ids or []
    )

    # Assign a test ID after construction.
    event.event_id = event_id
    return event


def main():
    root = create_event(
        "ATK-TEST-001",
        "GOAL_HIJACKING"
    )

    memory = create_event(
        "ATK-TEST-002",
        "SESSION_CONTEXT_CONTAMINATION",
        ["ATK-TEST-001"]
    )

    trust = create_event(
        "ATK-TEST-003",
        "INTER_AGENT_TRUST_ESCALATION",
        ["ATK-TEST-002"]
    )

    mcp = create_event(
        "ATK-TEST-004",
        "MCP_TOOL_ABUSE",
        ["ATK-TEST-001"]
    )

    paths = [
        [root, memory, trust],
        [root, mcp]
    ]

    report = SecurityReport().generate_adaptive_report(
        paths,
        disabled_controls={"GOAL_VALIDATION"}
    )

    assert report["branch_count"] == 2
    assert report["effective_branches"] == 2
    assert report["ineffective_branches"] == 0

    first, second = report["branches"]

    assert first["blocked_at"] == "SESSION_CONTEXT_CONTAMINATION"
    assert first["blocked_control"] == "MEMORY_PROVENANCE_CHECK"

    assert second["blocked_at"] == "MCP_TOOL_ABUSE"
    assert second["blocked_control"] == "MCP_PROVENANCE_CHECK"

    assert first["remaining_exploitable"] is False
    assert second["remaining_exploitable"] is False

    print("PASS: Both branches tested with GOAL_VALIDATION disabled.")
    print("PASS: Memory provenance blocked the first branch.")
    print("PASS: MCP provenance blocked the second branch.")
    print("PASS: Adaptive report correctly summarizes results.")
    print("ADAPTIVE SECURITY REPORT TEST PASSED")


if __name__ == "__main__":
    main()
