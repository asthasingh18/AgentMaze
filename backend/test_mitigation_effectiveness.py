from app.security.retest_engine import RetestEngine


class MockEvent:
    def __init__(self, event_type):
        self.event_id = f"TEST-{event_type}"
        self.event_type = event_type
        self.agent_id = "A001"
        self.severity = "HIGH"


def run_test():
    print("\n=== MITIGATION EFFECTIVENESS TESTS ===")

    # Test 1: Memory control blocks context contamination
    engine = RetestEngine()
    engine.blocked_controls.add("MEMORY_PROVENANCE_CHECK")

    result = engine.retest_path([
        MockEvent("SESSION_CONTEXT_CONTAMINATION")
    ])

    assert result["status"] == "PASS"
    assert result["blocked_control"] == "MEMORY_PROVENANCE_CHECK"
    print("PASS: Memory provenance control blocks context contamination.")

    # Test 2: MCP control blocks tool abuse
    engine = RetestEngine()
    engine.blocked_controls.add("MCP_PROVENANCE_CHECK")

    result = engine.retest_path([
        MockEvent("MCP_TOOL_ABUSE")
    ])

    assert result["status"] == "PASS"
    assert result["blocked_control"] == "MCP_PROVENANCE_CHECK"
    print("PASS: MCP provenance control blocks tool abuse.")

    # Test 3: Unrelated control must not block MCP tool abuse
    engine = RetestEngine()
    engine.blocked_controls.add("MEMORY_PROVENANCE_CHECK")

    result = engine.retest_path([
        MockEvent("MCP_TOOL_ABUSE")
    ])

    assert result["status"] == "FAIL"
    assert result["blocked_at"] is None
    print("PASS: Unrelated control does not block MCP tool abuse.")

    # Test 4: Without controls, the attack path remains exploitable
    engine = RetestEngine()

    result = engine.retest_path([
        MockEvent("SESSION_CONTEXT_CONTAMINATION"),
        MockEvent("INTER_AGENT_TRUST_ESCALATION")
    ])

    assert result["status"] == "FAIL"
    assert len(result["executed_steps"]) == 2
    print("PASS: Attack path remains exploitable without mitigation.")

    print("\nALL MITIGATION EFFECTIVENESS TESTS PASSED.")

def test_branch_specific_controls_without_root_control():
    # Branch 1: Memory provenance control
    memory_engine = RetestEngine()
    memory_engine.blocked_controls.add("MEMORY_PROVENANCE_CHECK")

    memory_result = memory_engine.retest_path([
        MockEvent("SESSION_CONTEXT_CONTAMINATION")
    ])

    assert memory_result["status"] == "PASS"
    assert memory_result["blocked_control"] == "MEMORY_PROVENANCE_CHECK"

    # Branch 2: MCP provenance control
    mcp_engine = RetestEngine()
    mcp_engine.blocked_controls.add("MCP_PROVENANCE_CHECK")

    mcp_result = mcp_engine.retest_path([
        MockEvent("MCP_TOOL_ABUSE")
    ])

    assert mcp_result["status"] == "PASS"
    assert mcp_result["blocked_control"] == "MCP_PROVENANCE_CHECK"

    print("PASS: Branch-specific controls work without GOAL_VALIDATION.")


test_branch_specific_controls_without_root_control()    


if __name__ == "__main__":
    run_test()


