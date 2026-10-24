
from unittest.mock import patch

from app.security.security_analytics import SecurityAnalytics


def make_event(event_type="GOAL_HIJACKING", severity="HIGH"):
    return type(
        "FakeEvent",
        (),
        {
            "event_type": event_type,
            "severity": severity,
        },
    )()


def make_path(*events):
    return list(events)


def test_empty_paths_returns_zero_summary():
    analytics = SecurityAnalytics()

    result = analytics.generate_summary([])

    assert result["status"] == "NO_PATHS"
    assert result["path_count"] == 0
    assert result["average_risk_score"] == 0
    assert result["blocked_paths"] == 0
    assert result["exploitable_paths"] == 0
    assert result["blocking_percentage"] == 0
    assert result["event_frequency"] == {}
    assert result["potential_control_weaknesses"] == {}


def test_summary_counts_blocked_paths_and_event_frequency():
    analytics = SecurityAnalytics()

    path = make_path(
        make_event("GOAL_HIJACKING", "HIGH"),
        make_event("INTER_AGENT_TRUST_ESCALATION", "MEDIUM"),
    )

    with (
        patch.object(
            analytics.mitigation_engine,
            "generate_plan",
            return_value={"controls": []},
        ),
        patch(
            "app.security.security_analytics.RetestEngine"
        ) as mock_engine,
    ):
        mock_engine.return_value.retest_path.return_value = {
            "status": "PASS"
        }

        result = analytics.generate_summary([path])

    assert result["status"] == "GENERATED"
    assert result["path_count"] == 1
    assert result["blocked_paths"] == 1
    assert result["exploitable_paths"] == 0
    assert result["manual_review_paths"] == 0
    assert result["blocking_percentage"] == 100.0
    assert result["evaluated_paths"] == 1
    assert result["event_frequency"] == {
        "GOAL_HIJACKING": 1,
        "INTER_AGENT_TRUST_ESCALATION": 1,
    }


def test_summary_counts_exploitable_paths_and_control_weaknesses():
    analytics = SecurityAnalytics()

    path = make_path(
        make_event("GOAL_HIJACKING", "HIGH"),
        make_event("GOAL_HIJACKING", "HIGH"),
    )

    with (
        patch.object(
            analytics.mitigation_engine,
            "generate_plan",
            return_value={"controls": []},
        ),
        patch(
            "app.security.security_analytics.RetestEngine"
        ) as mock_engine,
    ):
        engine = mock_engine.return_value
        engine.retest_path.return_value = {"status": "FAIL"}
        engine.get_required_control.return_value = "GOAL_VALIDATION"

        result = analytics.generate_summary([path])

    assert result["blocked_paths"] == 0
    assert result["exploitable_paths"] == 1
    assert result["blocking_percentage"] == 0.0
    assert result["potential_control_weaknesses"] == {
        "GOAL_VALIDATION": 2
    }
    assert result["evaluated_paths"] == 1


def test_unknown_event_paths_are_sent_for_manual_review():
    analytics = SecurityAnalytics()

    path = make_path(make_event("UNRECOGNIZED_EVENT", "LOW"))

    with (
        patch.object(
            analytics.mitigation_engine,
            "generate_plan",
            return_value={"controls": []},
        ),
        patch(
            "app.security.security_analytics.RetestEngine"
        ) as mock_engine,
    ):
        mock_engine.return_value.retest_path.return_value = {
            "status": "UNKNOWN_EVENT"
        }

        result = analytics.generate_summary([path])

    assert result["manual_review_paths"] == 1
    assert result["blocked_paths"] == 0
    assert result["exploitable_paths"] == 0
    assert result["evaluated_paths"] == 0


def test_summary_calculates_average_risk_and_distribution():
    analytics = SecurityAnalytics()

    paths = [
        make_path(make_event("EVENT_LOW", "LOW")),
        make_path(make_event("EVENT_HIGH", "HIGH")),
    ]

    with (
        patch.object(
            analytics.mitigation_engine,
            "generate_plan",
            return_value={"controls": []},
        ),
        patch(
            "app.security.security_analytics.RetestEngine"
        ) as mock_engine,
    ):
        mock_engine.return_value.retest_path.return_value = {
            "status": "PASS"
        }

        result = analytics.generate_summary(paths)

    assert result["path_count"] == 2
    assert result["risk_distribution"]["LOW"] == 2
    assert result["risk_distribution"]["MEDIUM"] == 0
    assert result["risk_distribution"]["HIGH"] == 0
    assert result["average_risk_score"] == 2.0
    assert result["blocking_percentage"] == 100.0
