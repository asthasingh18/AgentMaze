
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


def test_branch_specific_controls():
    engine = RetestEngine()

    # Test session-context mitigation independently.
    context = make_event(
        "SESSION_CONTEXT_CONTAMINATION",
        "TEST-101"
    )

    trust = make_event(
        "INTER_AGENT_TRUST_ESCALATION",
        "TEST-102",
        ["TEST-101"]
    )

    engine.apply_mitigation({
        "controls": ["MEMORY_PROVENANCE_CHECK"],
        "actions": [{
            "event": "SESSION_CONTEXT_CONTAMINATION",
            "control": "MEMORY_PROVENANCE_CHECK",
            "action": "Isolate untrusted memory"
        }]
    })

    result = engine.retest_path([context, trust])

    assert result["status"] == "PASS"
    assert result["blocked_at"] == "SESSION_CONTEXT_CONTAMINATION"
    assert result["blocked_control"] == "MEMORY_PROVENANCE_CHECK"
    print("PASS: Memory provenance control blocks its branch.")

    # Test MCP tool-abuse mitigation independently.
    engine = RetestEngine()

    mcp = make_event("MCP_TOOL_ABUSE", "TEST-103")

    engine.apply_mitigation({
        "controls": ["MCP_PROVENANCE_CHECK"],
        "actions": [{
            "event": "MCP_TOOL_ABUSE",
            "control": "MCP_PROVENANCE_CHECK",
            "action": "Validate tool provenance"
        }]
    })

    result = engine.retest_path([mcp])

    assert result["status"] == "PASS"
    assert result["blocked_at"] == "MCP_TOOL_ABUSE"
    assert result["blocked_control"] == "MCP_PROVENANCE_CHECK"
    print("PASS: MCP provenance control blocks tool abuse.")

    # Confirm an unrelated control does not block MCP tool abuse.
    engine = RetestEngine()

    engine.apply_mitigation({
        "controls": ["MEMORY_PROVENANCE_CHECK"],
        "actions": [{
            "event": "SESSION_CONTEXT_CONTAMINATION",
            "control": "MEMORY_PROVENANCE_CHECK",
            "action": "Isolate untrusted memory"
        }]
    })

    result = engine.retest_path([mcp])

    assert result["status"] == "FAIL"
    assert result["blocked_at"] is None
    print("PASS: An unrelated control does not block MCP tool abuse.")

    print("BRANCH-SPECIFIC RETEST TESTS PASSED")


if __name__ == "__main__":
    test_branch_specific_controls()
