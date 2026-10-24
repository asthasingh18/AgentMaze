
from unittest.mock import MagicMock, patch

from app.security.security_report import SecurityReport


def test_generate_report_with_no_path():
    report = SecurityReport()

    result = report.generate_report([])

    assert result["status"] == "NO_PATH"
    assert result["risk"] is None
    assert result["explanation"] is None
    assert result["mitigation_plan"] is None
    assert result["retest"] is None


def test_generate_branch_report_with_no_paths():
    report = SecurityReport()

    result = report.generate_branch_report([])

    assert result["status"] == "NO_PATHS"
    assert result["branches"] == []
    assert result["overall_status"] == "NOT_TESTED"
    assert result["effectiveness_percentage"] == 0


def test_generate_adaptive_report_with_no_paths():
    report = SecurityReport()

    result = report.generate_adaptive_report([])

    assert result["status"] == "NO_PATHS"
    assert result["branches"] == []
    assert result["overall_status"] == "NOT_TESTED"
    assert result["effectiveness_percentage"] == 0


def test_generate_analytics_report_delegates_to_analytics():
    report = SecurityReport()
    paths = [["sample-path"]]
    expected = {"total_paths": 1}

    report.security_analytics.generate_summary = MagicMock(
        return_value=expected
    )

    result = report.generate_analytics_report(paths)

    assert result == expected
    report.security_analytics.generate_summary.assert_called_once_with(
        paths
    )


def test_generate_recovery_report_delegates_to_evaluator():
    report = SecurityReport()
    paths = [["sample-path"]]
    failed_controls = ["GOAL_VALIDATION"]
    expected = {"status": "EVALUATED"}

    report.recovery_evaluator.evaluate = MagicMock(
        return_value=expected
    )

    result = report.generate_recovery_report(
        paths,
        failed_controls=failed_controls,
    )

    assert result == expected
    report.recovery_evaluator.evaluate.assert_called_once_with(
        paths,
        failed_controls=failed_controls,
    )



def test_generate_report_with_path():
    report = SecurityReport()

    event = MagicMock()
    event.event_id = "ATK-001"
    event.event_type = "GOAL_HIJACKING"
    event.agent_id = "A001"
    event.severity = "HIGH"

    path = [event]

    report.risk_scorer.score_path = MagicMock(
        return_value={"score": 3, "level": "LOW"}
    )
    report.path_explainer.explain_path = MagicMock(
        return_value={"summary": "Test explanation"}
    )
    report.mitigation_engine.generate_plan = MagicMock(
        return_value={"actions": []}
    )
    report.retest_engine.apply_mitigation = MagicMock()

    with patch(
        "app.security.security_report.RetestEngine"
    ) as mock_retest_class:
        mock_retest_engine = MagicMock()
        mock_retest_engine.retest_path.side_effect = [
            {"status": "FAIL"},
            {"status": "PASS"},
        ]

        mock_retest_class.return_value = mock_retest_engine

        # The report uses RetestEngine() for before_retest,
        # and the existing self.retest_engine for after_retest.
        report.retest_engine.retest_path = MagicMock(
            return_value={"status": "PASS"}
        )

        result = report.generate_report(path)

    assert result["status"] == "GENERATED"
    assert result["path"][0]["event_id"] == "ATK-001"
    assert result["path"][0]["event_type"] == "GOAL_HIJACKING"
    assert result["risk"] == {"score": 3, "level": "LOW"}
    assert result["explanation"] == {
        "summary": "Test explanation"
    }
    assert result["mitigation_plan"] == {"actions": []}
    assert result["before_retest"]["status"] == "FAIL"
    assert result["after_retest"]["status"] == "PASS"

    report.retest_engine.apply_mitigation.assert_called_once_with(
        {"actions": []}
    )


def test_generate_branch_report_with_effective_mitigation():
    report = SecurityReport()

    event = MagicMock()
    event.event_type = "GOAL_HIJACKING"
    path = [event]

    report.risk_scorer.score_path = MagicMock(
        return_value={"score": 3, "level": "LOW"}
    )
    report.mitigation_engine.generate_plan = MagicMock(
        return_value={"actions": []}
    )

    with patch(
        "app.security.security_report.RetestEngine"
    ) as mock_retest_class:
        mock_engine = MagicMock()
        mock_engine.retest_path.side_effect = [
            {"status": "FAIL"},
            {
                "status": "PASS",
                "blocked_at": "GOAL_VALIDATION",
                "blocked_control": "GOAL_VALIDATION",
            },
        ]
        mock_retest_class.return_value = mock_engine

        result = report.generate_branch_report([path])

    assert result["status"] == "GENERATED"
    assert result["branch_count"] == 1
    assert result["effective_branches"] == 1
    assert result["ineffective_branches"] == 0
    assert result["manual_review_branches"] == 0
    assert result["effectiveness_percentage"] == 100.0
    assert result["overall_status"] == "PASS"
    assert (
        result["branches"][0]["mitigation_effectiveness"]["effectiveness"]
        == "EFFECTIVE"
    )


def test_generate_branch_report_with_manual_review():
    report = SecurityReport()

    event = MagicMock()
    event.event_type = "UNKNOWN_EVENT"
    path = [event]

    report.risk_scorer.score_path = MagicMock(
        return_value={"score": 0, "level": "UNKNOWN"}
    )
    report.mitigation_engine.generate_plan = MagicMock(
        return_value={"actions": []}
    )

    with patch(
        "app.security.security_report.RetestEngine"
    ) as mock_retest_class:
        mock_engine = MagicMock()
        mock_engine.retest_path.side_effect = [
            {"status": "UNKNOWN_EVENT"},
            {"status": "UNKNOWN_EVENT"},
        ]
        mock_retest_class.return_value = mock_engine

        result = report.generate_branch_report([path])

    assert result["status"] == "GENERATED"
    assert result["manual_review_branches"] == 1
    assert result["evaluated_branches"] == 0
    assert result["effectiveness_percentage"] == 0
    assert result["overall_status"] == "FAIL"
    assert (
        result["branches"][0]["mitigation_effectiveness"]["effectiveness"]
        == "MANUAL_REVIEW"
    )


def test_generate_branch_report_with_ineffective_mitigation():
    report = SecurityReport()

    event = MagicMock()
    event.event_type = "GOAL_HIJACKING"
    path = [event]

    report.risk_scorer.score_path = MagicMock(
        return_value={"score": 3, "level": "LOW"}
    )
    report.mitigation_engine.generate_plan = MagicMock(
        return_value={"actions": []}
    )

    with patch(
        "app.security.security_report.RetestEngine"
    ) as mock_retest_class:
        mock_engine = MagicMock()
        mock_engine.retest_path.side_effect = [
            {"status": "FAIL"},
            {"status": "FAIL"},
        ]
        mock_retest_class.return_value = mock_engine

        result = report.generate_branch_report([path])

    assert result["ineffective_branches"] == 1
    assert result["effective_branches"] == 0
    assert result["evaluated_branches"] == 1
    assert result["effectiveness_percentage"] == 0.0
    assert result["overall_status"] == "FAIL"
    assert (
        result["branches"][0]["mitigation_effectiveness"]["effectiveness"]
        == "INEFFECTIVE"
    )


def test_generate_adaptive_report_with_effective_mitigation():
    report = SecurityReport()

    event = MagicMock()
    event.event_type = "GOAL_HIJACKING"
    path = [event]

    report.mitigation_engine.generate_plan = MagicMock(
        return_value={"actions": []}
    )

    with patch(
        "app.security.security_report.RetestEngine"
    ) as mock_retest_class:
        mock_engine = MagicMock()
        mock_engine.retest_path_with_disabled_controls.return_value = {
            "status": "PASS",
            "executed_steps": ["GOAL_VALIDATION"],
            "blocked_at": "GOAL_VALIDATION",
            "blocked_control": "GOAL_VALIDATION",
            "message": "Attack path blocked",
        }
        mock_retest_class.return_value = mock_engine

        result = report.generate_adaptive_report([path])

    assert result["status"] == "GENERATED"
    assert result["branch_count"] == 1
    assert result["effective_branches"] == 1
    assert result["ineffective_branches"] == 0
    assert result["effectiveness_percentage"] == 100.0
    assert result["overall_status"] == "PASS"
    assert result["disabled_controls"] == ["GOAL_VALIDATION"]
    assert result["branches"][0]["remaining_exploitable"] is False


def test_generate_adaptive_report_with_ineffective_mitigation():
    report = SecurityReport()

    event = MagicMock()
    event.event_type = "GOAL_HIJACKING"
    path = [event]

    report.mitigation_engine.generate_plan = MagicMock(
        return_value={"actions": []}
    )

    with patch(
        "app.security.security_report.RetestEngine"
    ) as mock_retest_class:
        mock_engine = MagicMock()
        mock_engine.retest_path_with_disabled_controls.return_value = {
            "status": "FAIL",
            "executed_steps": ["GOAL_HIJACKING"],
            "blocked_at": None,
            "blocked_control": None,
            "message": "Attack path remains exploitable",
        }
        mock_retest_class.return_value = mock_engine

        result = report.generate_adaptive_report(
            [path],
            disabled_controls=["GOAL_VALIDATION"],
        )

    assert result["status"] == "GENERATED"
    assert result["effective_branches"] == 0
    assert result["ineffective_branches"] == 1
    assert result["effectiveness_percentage"] == 0.0
    assert result["overall_status"] == "FAIL"
    assert result["branches"][0]["remaining_exploitable"] is True


def test_generate_adaptive_report_sorts_disabled_controls():
    report = SecurityReport()

    event = MagicMock()
    event.event_type = "GOAL_HIJACKING"
    path = [event]

    report.mitigation_engine.generate_plan = MagicMock(
        return_value={"actions": []}
    )

    with patch(
        "app.security.security_report.RetestEngine"
    ) as mock_retest_class:
        mock_engine = MagicMock()
        mock_engine.retest_path_with_disabled_controls.return_value = {
            "status": "PASS",
            "executed_steps": [],
            "blocked_at": None,
            "blocked_control": None,
            "message": "Test completed",
        }
        mock_retest_class.return_value = mock_engine

        result = report.generate_adaptive_report(
            [path],
            disabled_controls=["TOOL_PERMISSION", "GOAL_VALIDATION"],
        )

    assert result["disabled_controls"] == [
        "GOAL_VALIDATION",
        "TOOL_PERMISSION",
    ]
    assert result["branches"][0]["disabled_controls"] == [
        "GOAL_VALIDATION",
        "TOOL_PERMISSION",
    ]
