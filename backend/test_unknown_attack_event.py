from types import SimpleNamespace

from app.security.retest_engine import RetestEngine


def test_unknown_attack_event_requires_manual_review():
    engine = RetestEngine()

    unknown_event = SimpleNamespace(
        event_id="TEST-UNKNOWN-001",
        event_type="UNKNOWN_EVENT",
        agent_id="TEST-AGENT",
        severity="HIGH",
    )

    result = engine.retest_path([unknown_event])

    assert result["status"] == "UNKNOWN_EVENT"
    assert result["executed_steps"] == []
    assert result["unknown_event"] == "UNKNOWN_EVENT"
    assert "Manual security review is required." in result["message"]