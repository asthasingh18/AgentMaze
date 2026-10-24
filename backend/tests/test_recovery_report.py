
from app.security.attack_event import AttackEvent
from app.security.security_report import SecurityReport


def test_security_report_integrates_recovery_evaluator():
    event = AttackEvent(
        event_type="GOAL_HIJACKING",
        agent_id="A001",
        description="Test goal hijacking event",
        severity="HIGH",
    )
    event.event_id = "REPORT-001"

    report = SecurityReport().generate_recovery_report(
        [[event]],
        failed_controls={"GOAL_VALIDATION"},
    )

    assert report["status"] == "GENERATED"
    assert report["branch_count"] == 1
    assert report["recovery_attempts"] == 1
    assert report["recovery_successes"] == 1
    assert report["recovery_success_percentage"] == 100
