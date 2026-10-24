from app.security.mitigation_engine import MitigationEngine


def test_validates_known_attack_event():
    engine = MitigationEngine()

    result = engine.validate_mitigation("GOAL_HIJACKING")

    assert result["valid"] is True
    assert result["event"] == "GOAL_HIJACKING"
    assert result["control"] == "GOAL_VALIDATION"


def test_flags_unknown_attack_event():
    engine = MitigationEngine()

    result = engine.validate_mitigation("UNKNOWN_EVENT")

    assert result["valid"] is False
    assert result["event"] == "UNKNOWN_EVENT"
    assert result["control"] == "MANUAL_REVIEW"

def test_all_known_events_have_expected_controls():
    engine = MitigationEngine()

    expected_controls = {
        "GOAL_HIJACKING": "GOAL_VALIDATION",
        "SESSION_CONTEXT_CONTAMINATION": "MEMORY_PROVENANCE_CHECK",
        "INTER_AGENT_TRUST_ESCALATION": "CAPABILITY_VERIFICATION",
        "MCP_TOOL_ABUSE": "MCP_PROVENANCE_CHECK",
        "MCP_PLUGIN_ABUSE": "MCP_PROVENANCE_CHECK",
        "CAPABILITY_ABUSE": "CAPABILITY_ENFORCEMENT",
    }

    for event_type, expected_control in expected_controls.items():
        result = engine.validate_mitigation(event_type)

        assert result["valid"] is True
        assert result["control"] == expected_control    