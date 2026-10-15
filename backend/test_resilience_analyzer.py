
from app.security.attack_event import AttackEvent
from app.security.resilience_analyzer import ResilienceAnalyzer


def create_event(event_id, event_type, parent_event_ids=None):
    event = AttackEvent(
        event_type=event_type,
        agent_id="A001",
        description=f"Resilience test: {event_type}",
        severity="HIGH",
        parent_event_ids=parent_event_ids or []
    )
    event.event_id = event_id
    return event


def main():
    root = create_event("RA-001", "GOAL_HIJACKING")

    memory = create_event(
        "RA-002",
        "SESSION_CONTEXT_CONTAMINATION",
        ["RA-001"]
    )

    trust = create_event(
        "RA-003",
        "INTER_AGENT_TRUST_ESCALATION",
        ["RA-002"]
    )

    mcp = create_event(
        "RA-004",
        "MCP_TOOL_ABUSE",
        ["RA-001"]
    )

    paths = [
        [root, memory, trust],
        [root, mcp]
    ]

    report = ResilienceAnalyzer().analyze(paths)

    assert report["status"] == "GENERATED"
    assert report["scenario_count"] == 5
    assert report["branch_count"] == 2
    assert report["total_tests"] == 10
    assert report["vulnerable_tests"] > 0
    assert report["overall_status"] == "VULNERABLE"
    assert report["vulnerable_tests"] == 3
    assert report["resilience_percentage"] == 70.0

    print("Scenarios tested:", report["scenario_count"])
    print("Attack branches:", report["branch_count"])
    print("Total retests:", report["total_tests"])
    print("Vulnerable retests:", report["vulnerable_tests"])
    print("Resilience percentage:", report["resilience_percentage"], "%")
    print("Overall status:", report["overall_status"])

    print("\nVulnerable branches:")
    for branch in report["vulnerable_branches"]:
        print(
            f"Branch {branch['branch']}: "
            f"{' -> '.join(branch['attack_sequence'])}"
        )
        print("Vulnerable scenarios:", branch["vulnerable_scenarios"])

    print("\nRESILIENCE ANALYZER TEST PASSED")


if __name__ == "__main__":
    main()
