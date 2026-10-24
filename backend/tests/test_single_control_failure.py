
from app.security.security_report import SecurityReport
from app.security.attack_event import AttackEvent
from app.security.retest_engine import RetestEngine


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
    root = create_event("RES-001", "GOAL_HIJACKING")

    memory = create_event(
        "RES-002",
        "SESSION_CONTEXT_CONTAMINATION",
        ["RES-001"]
    )

    trust = create_event(
        "RES-003",
        "INTER_AGENT_TRUST_ESCALATION",
        ["RES-002"]
    )

    mcp = create_event(
        "RES-004",
        "MCP_TOOL_ABUSE",
        ["RES-001"]
    )

    paths = [
        [root, memory, trust],
        [root, mcp]
    ]

    report_service = SecurityReport()
    control_failures = [
        "GOAL_VALIDATION",
        "MEMORY_PROVENANCE_CHECK",
        "CAPABILITY_VERIFICATION",
        "MCP_PROVENANCE_CHECK"
    ]

    print("=== SINGLE-CONTROL FAILURE EXPERIMENT ===")

    for disabled_control in control_failures:
        print(f"\nDisabled control: {disabled_control}")

        for index, path in enumerate(paths, start=1):
            plan = report_service.mitigation_engine.generate_plan(path)

            engine = RetestEngine()
            engine.apply_mitigation(plan)

            result = engine.retest_path_with_disabled_controls(
                path,
                {disabled_control}
            )

            print(f"Branch {index}: {result['status']}")
            print("  Blocked at:", result.get("blocked_at"))
            print("  Blocking control:", result.get("blocked_control"))
            print(
                "  Remaining exploitable:",
                result["status"] != "PASS"
            )

    print("\nSINGLE-CONTROL FAILURE EXPERIMENT COMPLETED")


if __name__ == "__main__":
    main()
