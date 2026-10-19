from app.security.recovery_evaluator import RecoveryEvaluator


def test_no_paths_returns_not_tested():
    evaluator = RecoveryEvaluator()

    result = evaluator.evaluate([])

    assert result["status"] == "NO_PATHS"
    assert result["overall_status"] == "NOT_TESTED"
    assert result["branch_count"] == 0


def test_unknown_attack_event_is_not_reported_as_recovered():
    from types import SimpleNamespace

    evaluator = RecoveryEvaluator()

    unknown_event = SimpleNamespace(
        event_id="TEST-UNKNOWN-002",
        event_type="UNKNOWN_EVENT",
        agent_id="TEST-AGENT",
        severity="HIGH",
    )

    result = evaluator.evaluate([[unknown_event]])

    assert result["overall_status"] != "RECOVERED"
    assert result["unknown_event_count"] == 1
    assert result["fully_evaluated_branches"] == 0