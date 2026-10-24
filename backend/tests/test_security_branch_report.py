
from app.security.attack_event import AttackEvent
from app.security.security_report import SecurityReport


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


def test_branch_report():
    root = make_event("GOAL_HIJACKING", "TEST-201")

    context = make_event(
        "SESSION_CONTEXT_CONTAMINATION",
        "TEST-202",
        ["TEST-201"]
    )

    trust = make_event(
        "INTER_AGENT_TRUST_ESCALATION",
        "TEST-203",
        ["TEST-202"]
    )

    mcp = make_event(
        "MCP_TOOL_ABUSE",
        "TEST-204",
        ["TEST-201"]
    )

    paths = [
        [root, context, trust],
        [root, mcp]
    ]

    report = SecurityReport().generate_branch_report(paths)

    assert report["status"] == "GENERATED"
    assert report["branch_count"] == 2
    assert len(report["branches"]) == 2

    assert report["branches"][0]["attack_sequence"] == [
        "GOAL_HIJACKING",
        "SESSION_CONTEXT_CONTAMINATION",
        "INTER_AGENT_TRUST_ESCALATION"
    ]

    assert report["branches"][1]["attack_sequence"] == [
        "GOAL_HIJACKING",
        "MCP_TOOL_ABUSE"
    ]

    for branch in report["branches"]:
        assert branch["before_retest"]["status"] == "FAIL"
        assert branch["after_retest"]["status"] == "PASS"

    print("PASS: Both attack branches appear in the report.")
    print("PASS: Each branch has separate mitigation and retest results.")
    print("Overall status:", report["overall_status"])
    print("SECURITY BRANCH REPORT TEST PASSED")


if __name__ == "__main__":
    test_branch_report()
