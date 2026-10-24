
from unittest.mock import patch

from app.security.recovery_evaluator import RecoveryEvaluator


def make_path():
    """Create a minimal event path for testing."""
    return [
        type(
            "FakeEvent",
            (),
            {"event_type": "GOAL_HIJACKING"},
        )()
    ]


def mock_plan(*args, **kwargs):
    return {"controls": ["GOAL_VALIDATION"]}


def test_evaluate_empty_paths():
    evaluator = RecoveryEvaluator()

    result = evaluator.evaluate([])

    assert result["status"] == "NO_PATHS"
    assert result["branch_count"] == 0
    assert result["overall_status"] == "NOT_TESTED"
    assert result["results"] == []


def test_unknown_event_is_reported():
    evaluator = RecoveryEvaluator()

    with (
        patch.object(
            evaluator.mitigation_engine,
            "generate_plan",
            side_effect=mock_plan,
        ),
        patch(
            "app.security.recovery_evaluator.RetestEngine"
        ) as mock_engine,
    ):
        baseline_engine = mock_engine.return_value
        baseline_engine.retest_path.return_value = {
            "status": "UNKNOWN_EVENT"
        }
        baseline_engine.retest_path_with_disabled_controls.return_value = {
            "status": "UNKNOWN_EVENT"
        }

        result = evaluator.evaluate([make_path()])

    assert result["results"][0]["recovery_status"] == "UNKNOWN_EVENT"
    assert result["unknown_event_count"] == 1
    assert result["fully_evaluated_branches"] == 0


def test_recovery_not_needed_when_failure_test_passes():
    evaluator = RecoveryEvaluator()

    with (
        patch.object(
            evaluator.mitigation_engine,
            "generate_plan",
            side_effect=mock_plan,
        ),
        patch(
            "app.security.recovery_evaluator.RetestEngine"
        ) as mock_engine,
    ):
        mock_engine.return_value.retest_path.return_value = {
            "status": "PASS"
        }
        mock_engine.return_value.retest_path_with_disabled_controls.return_value = {
            "status": "PASS"
        }

        result = evaluator.evaluate([make_path()])

    assert result["results"][0]["recovery_status"] == "RECOVERY_NOT_NEEDED"
    assert result["recovery_attempts"] == 0
    assert result["overall_status"] == "RECOVERY_NOT_NEEDED"


def test_baseline_not_protected_when_baseline_fails():
    evaluator = RecoveryEvaluator()

    with (
        patch.object(
            evaluator.mitigation_engine,
            "generate_plan",
            side_effect=mock_plan,
        ),
        patch(
            "app.security.recovery_evaluator.RetestEngine"
        ) as mock_engine,
    ):
        mock_engine.return_value.retest_path.return_value = {
            "status": "FAIL"
        }
        mock_engine.return_value.retest_path_with_disabled_controls.return_value = {
            "status": "FAIL"
        }

        result = evaluator.evaluate([make_path()])

    assert result["results"][0]["recovery_status"] == "BASELINE_NOT_PROTECTED"
    assert result["recovery_failures"] == 1
    assert result["overall_status"] == "RECOVERY_INCOMPLETE"


def test_failed_controls_are_sorted():
    evaluator = RecoveryEvaluator()

    with (
        patch.object(
            evaluator.mitigation_engine,
            "generate_plan",
            side_effect=mock_plan,
        ),
        patch(
            "app.security.recovery_evaluator.RetestEngine"
        ) as mock_engine,
    ):
        mock_engine.return_value.retest_path.return_value = {
            "status": "PASS"
        }
        mock_engine.return_value.retest_path_with_disabled_controls.return_value = {
            "status": "PASS"
        }

        result = evaluator.evaluate(
            [make_path()],
            failed_controls={"TOOL_AUTHORIZATION", "GOAL_VALIDATION"},
        )

    assert result["failed_controls"] == [
        "GOAL_VALIDATION",
        "TOOL_AUTHORIZATION",
    ]
    assert result["results"][0]["failed_controls"] == [
        "GOAL_VALIDATION",
        "TOOL_AUTHORIZATION",
    ]
