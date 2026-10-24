
from app.security.attack_event import AttackEvent
from app.security.mitigation_engine import MitigationEngine
from app.security.retest_engine import RetestEngine


def create_event(event_id, event_type, parent_event_ids=None):
    event = AttackEvent(
        event_type=event_type,
        agent_id="A001",
        description=f"Multiple-control test: {event_type}",
        severity="HIGH",
        parent_event_ids=parent_event_ids or []
    )
    event.event_id = event_id
    return event


def main():
    root = create_event("MULTI-001", "GOAL_HIJACKING")
    memory = create_event(
        "MULTI-002",
        "SESSION_CONTEXT_CONTAMINATION",
        ["MULTI-001"]
    )
    trust = create_event(
        "MULTI-003",
        "INTER_AGENT_TRUST_ESCALATION",
        ["MULTI-002"]
    )
    mcp = create_event(
        "MULTI-004",
        "MCP_TOOL_ABUSE",
        ["MULTI-001"]
    )

    paths = [
        ("Memory branch", [root, memory, trust]),
        ("MCP branch", [root, mcp])
    ]

    mitigation_engine = MitigationEngine()

    experiments = [
        ("No controls disabled", set()),
        ("Root control disabled", {"GOAL_VALIDATION"}),
        (
            "Root + memory controls disabled",
            {"GOAL_VALIDATION", "MEMORY_PROVENANCE_CHECK"}
        ),
        (
            "Root + MCP controls disabled",
            {"GOAL_VALIDATION", "MCP_PROVENANCE_CHECK"}
        ),
        (
            "All branch controls disabled",
            {
                "GOAL_VALIDATION",
                "MEMORY_PROVENANCE_CHECK",
                "CAPABILITY_VERIFICATION",
                "MCP_PROVENANCE_CHECK"
            }
        )
    ]

    print("=== MULTIPLE-CONTROL FAILURE EXPERIMENT ===")

    for experiment_name, disabled_controls in experiments:
        print(f"\nExperiment: {experiment_name}")
        print("Disabled controls:", sorted(disabled_controls))

        for branch_name, path in paths:
            plan = mitigation_engine.generate_plan(path)
            engine = RetestEngine()
            engine.apply_mitigation(plan)

            result = engine.retest_path_with_disabled_controls(
                path, disabled_controls
            )

            print(
                f"{branch_name}: {result['status']} | "
                f"Blocked at: {result.get('blocked_at')} | "
                f"Control: {result.get('blocked_control')} | "
                f"Exploitable: {result['status'] != 'PASS'}"
            )

    print("\nMULTIPLE-CONTROL FAILURE EXPERIMENT COMPLETED")


if __name__ == "__main__":
    main()
