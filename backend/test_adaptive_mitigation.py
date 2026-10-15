from app.security.retest_engine import RetestEngine


class MockEvent:
    def __init__(self, event_type):
        self.event_id = f"TEST-{event_type}"
        self.event_type = event_type
        self.agent_id = "A001"
        self.severity = "HIGH"


def test_adaptive_mitigation():
    print("\n=== ADAPTIVE MITIGATION TESTS ===")

    # Branch 1: Goal validation is unavailable.
    # Memory provenance should block context contamination.
    branch_one = [
        MockEvent("GOAL_HIJACKING"),
        MockEvent("SESSION_CONTEXT_CONTAMINATION"),
        MockEvent("INTER_AGENT_TRUST_ESCALATION")
    ]

    engine_one = RetestEngine()
    engine_one.blocked_controls.update({
        "GOAL_VALIDATION",
        "MEMORY_PROVENANCE_CHECK",
        "CAPABILITY_VERIFICATION"
    })

    result_one = engine_one.retest_path_with_disabled_controls(
        branch_one,
        {"GOAL_VALIDATION"}
    )

    assert result_one["status"] == "PASS"
    assert result_one["blocked_at"] == "SESSION_CONTEXT_CONTAMINATION"
    assert result_one["blocked_control"] == "MEMORY_PROVENANCE_CHECK"

    print("PASS: Branch 1 is blocked by memory provenance.")

    # Branch 2: Goal validation is unavailable.
    # MCP provenance should block tool abuse.
    branch_two = [
        MockEvent("GOAL_HIJACKING"),
        MockEvent("MCP_TOOL_ABUSE")
    ]

    engine_two = RetestEngine()
    engine_two.blocked_controls.update({
        "GOAL_VALIDATION",
        "MCP_PROVENANCE_CHECK"
    })

    result_two = engine_two.retest_path_with_disabled_controls(
        branch_two,
        {"GOAL_VALIDATION"}
    )

    assert result_two["status"] == "PASS"
    assert result_two["blocked_at"] == "MCP_TOOL_ABUSE"
    assert result_two["blocked_control"] == "MCP_PROVENANCE_CHECK"

    print("PASS: Branch 2 is blocked by MCP provenance.")

    # Negative test: Without remaining controls, the path stays exploitable.
    engine_three = RetestEngine()
    engine_three.blocked_controls.add("GOAL_VALIDATION")

    result_three = engine_three.retest_path_with_disabled_controls(
        branch_two,
        {"GOAL_VALIDATION"}
    )

    assert result_three["status"] == "FAIL"
    assert result_three["blocked_at"] is None

    print("PASS: Without remaining controls, the attack path remains exploitable.")
    print("\nALL ADAPTIVE MITIGATION TESTS PASSED.")


if __name__ == "__main__":
    test_adaptive_mitigation()