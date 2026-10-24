
from app.security.attack_event import AttackEvent
from app.security.mitigation_engine import MitigationEngine
from app.security.retest_engine import RetestEngine

test_cases = [
    ("GOAL_HIJACKING", "GOAL_VALIDATION"),
    ("SESSION_CONTEXT_CONTAMINATION", "MEMORY_PROVENANCE_CHECK"),
    ("INTER_AGENT_TRUST_ESCALATION", "CAPABILITY_VERIFICATION"),
    ("MCP_TOOL_ABUSE", "MCP_PROVENANCE_CHECK"),
    ("MCP_PLUGIN_ABUSE", "MCP_PROVENANCE_CHECK"),
    ("CAPABILITY_ABUSE", "CAPABILITY_ENFORCEMENT"),
]

mitigation_engine = MitigationEngine()

for event_type, expected_control in test_cases:
    event = AttackEvent(
        event_type=event_type,
        agent_id="TEST_AGENT",
        description="Controlled mitigation test",
        severity="HIGH",
    )

    plan = mitigation_engine.generate_plan([event])
    retest = RetestEngine()
    before = retest.retest_path([event])
    retest.apply_mitigation(plan)
    after = retest.retest_path([event])

    passed = (
        before["status"] == "FAIL"
        and after["status"] == "PASS"
        and after.get("blocked_control") == expected_control
    )

    print(
        f"{event_type}: {'PASS' if passed else 'FAIL'} "
        f"| Expected control: {expected_control} "
        f"| Actual control: {after.get('blocked_control')}"
    )

    if not passed:
        raise AssertionError(f"Mitigation coverage failed for {event_type}")

print("\nALL MITIGATION CONTROL TESTS PASSED")
