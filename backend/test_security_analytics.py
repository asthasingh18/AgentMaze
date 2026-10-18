
from app.security.attack_event import AttackEvent
from app.security.security_analytics import SecurityAnalytics
from app.security.security_report import SecurityReport


def create_event(event_id, event_type, severity="HIGH"):
    event = AttackEvent(
        event_type=event_type,
        agent_id="A001",
        description=f"Analytics test: {event_type}",
        severity=severity
    )
    event.event_id = event_id
    return event


def test_empty_paths_return_no_paths_status():
    report = SecurityAnalytics().generate_summary([])

    assert report["status"] == "NO_PATHS"
    assert report["path_count"] == 0
    assert report["average_risk_score"] == 0
    assert report["blocked_paths"] == 0
    assert report["exploitable_paths"] == 0


def test_risk_distribution_and_event_frequency():
    path_one = [
        create_event("SA-001", "GOAL_HIJACKING", "HIGH"),
        create_event(
            "SA-002",
            "SESSION_CONTEXT_CONTAMINATION",
            "HIGH"
        )
    ]

    path_two = [
        create_event("SA-003", "GOAL_HIJACKING", "LOW")
    ]

    report = SecurityAnalytics().generate_summary(
        [path_one, path_two]
    )

    assert report["status"] == "GENERATED"
    assert report["path_count"] == 2
    assert report["risk_distribution"]["MEDIUM"] == 1
    assert report["risk_distribution"]["LOW"] == 1
    assert report["event_frequency"]["GOAL_HIJACKING"] == 2
    assert report["event_frequency"]["SESSION_CONTEXT_CONTAMINATION"] == 1
    assert report["average_risk_score"] > 0


def test_retest_outcomes_and_percentages():
    path = [
        create_event("SA-011", "GOAL_HIJACKING", "HIGH"),
        create_event(
            "SA-012",
            "SESSION_CONTEXT_CONTAMINATION",
            "HIGH"
        )
    ]

    report = SecurityAnalytics().generate_summary([path])

    assert report["blocked_paths"] + report["exploitable_paths"] == 1
    assert report["blocking_percentage"] in (0, 100)
    assert 0 <= report["blocking_percentage"] <= 100

def test_security_report_integrates_analytics():
    event = create_event(
        "SA-101",
        "GOAL_HIJACKING",
        "HIGH"
    )

    report = SecurityReport().generate_analytics_report([[event]])

    assert report["status"] == "GENERATED"
    assert report["path_count"] == 1
    assert "risk_distribution" in report
    assert "event_frequency" in report
    assert "blocking_percentage" in report    
