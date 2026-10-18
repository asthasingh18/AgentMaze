
from app.security.attack_event import AttackEvent
from app.security.recovery_evaluator import RecoveryEvaluator


def create_event(event_id, event_type, severity="HIGH"):
    event = AttackEvent(
        event_type=event_type,
        agent_id="A001",
        description=f"Test event for {event_type}",
        severity=severity,
    )

    # Assign an ID for consistency with other project tests.
    event.event_id = event_id
    return event


def test_recovery_evaluator_handles_no_paths():
    result = RecoveryEvaluator().evaluate([])

    assert result["status"] == "NO_PATHS"
    assert result["branch_count"] == 0
    assert result["recovery_success_percentage"] == 0


def test_recovery_succeeds_after_simulated_control_failure():
    path = [create_event("REC-001", "GOAL_HIJACKING")]

    result = RecoveryEvaluator().evaluate(
        [path],
        failed_controls={"GOAL_VALIDATION"},
    )

    assert result["status"] == "GENERATED"
    assert result["branch_count"] == 1
    assert result["recovery_successes"] == 1
    assert result["recovery_failures"] == 0
    assert result["recovery_success_percentage"] == 100

    branch = result["results"][0]
    assert branch["baseline_status"] == "PASS"
    assert branch["failure_test_status"] == "FAIL"
    assert branch["recovery_status"] == "RECOVERED"


def test_recovery_is_not_attempted_when_failure_does_not_expose_path():
    path = [create_event("REC-002", "GOAL_HIJACKING")]

    result = RecoveryEvaluator().evaluate(
        [path],
        failed_controls={"MEMORY_PROVENANCE_CHECK"},
    )

    branch = result["results"][0]

    assert branch["baseline_status"] == "PASS"
    assert branch["failure_test_status"] == "PASS"
    assert branch["recovery_attempted"] is False
    assert branch["recovery_status"] == "RECOVERY_NOT_NEEDED"
    assert result["recovery_success_percentage"] == 0
