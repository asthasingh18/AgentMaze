
from app.security.mitigation_engine import MitigationEngine
from app.security.retest_engine import RetestEngine


class RecoveryEvaluator:
    """Evaluate recovery after simulated security-control failures."""

    def __init__(self):
        self.mitigation_engine = MitigationEngine()

    def evaluate(self, paths, failed_controls=None):
        if not paths:
            return {
                "status": "NO_PATHS",
                "branch_count": 0,
                "recovery_successes": 0,
                "recovery_failures": 0,
                "recovery_success_percentage": 0,
                "results": [],
                "overall_status": "NOT_TESTED",
            }

        if failed_controls is None:
            failed_controls = {"GOAL_VALIDATION"}
        else:
            failed_controls = set(failed_controls)

        results = []

        for branch_index, path in enumerate(paths, start=1):
            plan = self.mitigation_engine.generate_plan(path)

            # Establish the baseline with all planned controls enabled.
            baseline_engine = RetestEngine()
            baseline_engine.apply_mitigation(plan)
            baseline = baseline_engine.retest_path(path)

            # Simulate the selected controls failing.
            failure_engine = RetestEngine()
            failure_engine.apply_mitigation(plan)
            failure_result = (
                failure_engine.retest_path_with_disabled_controls(
                    path, failed_controls
                )
            )

            # Recovery is considered successful only when the baseline
            # was protected and the failure test exposed the path.
            
            recovery_attempted = (
                baseline["status"] == "PASS"
                and failure_result["status"] == "FAIL"
            )

            if recovery_attempted:
                recovery_engine = RetestEngine()
                recovery_engine.apply_mitigation(plan)
                recovery_result = recovery_engine.retest_path(path)
                recovered = recovery_result["status"] == "PASS"
                recovery_status = (
                    "RECOVERED" if recovered else "RECOVERY_FAILED"
                )
            elif (
                baseline["status"] == "UNKNOWN_EVENT"
                or failure_result["status"] == "UNKNOWN_EVENT"
            ):
                recovery_result = None
                recovered = False
                recovery_status = "UNKNOWN_EVENT"

            elif failure_result["status"] == "PASS":
                recovery_result = None
                recovered = False
                recovery_status = "RECOVERY_NOT_NEEDED"

            else:
                recovery_result = None
                recovered = False
                recovery_status = "BASELINE_NOT_PROTECTED"


            results.append({
                "branch": branch_index,
                "attack_sequence": [
                    event.event_type for event in path
                ],
                "failed_controls": sorted(failed_controls),
                "baseline_status": baseline["status"],
                "failure_test_status": failure_result["status"],
                "recovery_attempted": recovery_attempted,
                "recovery_status": recovery_status,
                "recovery_result": recovery_result,
            })

        recovery_successes = sum(
            result["recovery_status"] == "RECOVERED"
            for result in results
        )
        recovery_failures = sum(
            result["recovery_status"] in {
                "RECOVERY_FAILED",
                "BASELINE_NOT_PROTECTED",
            }
            for result in results
        )
        recovery_not_needed = sum(
            result["recovery_status"] == "RECOVERY_NOT_NEEDED"
            for result in results
        )
        unknown_events = sum(
            result["recovery_status"] == "UNKNOWN_EVENT"
            for result in results
)
        recovery_attempts = recovery_successes + sum(
            result["recovery_status"] == "RECOVERY_FAILED"
            for result in results
        )
        recovery_success_percentage = round(
            recovery_successes / recovery_attempts * 100, 2
        ) if recovery_attempts else 0

        percentage = round(
            recovery_successes / len(results) * 100, 2
        )

        return {
            "status": "GENERATED",
            "branch_count": len(results),
            "failed_controls": sorted(failed_controls),
            "recovery_successes": recovery_successes,
            "recovery_failures": recovery_failures,
            "recovery_attempts": recovery_attempts,
            "recovery_success_percentage": recovery_success_percentage,
            "results": results,
            "overall_status": (
                "RECOVERY_INCOMPLETE"
                if recovery_failures > 0
                else "RECOVERED"
                if recovery_attempts > 0
                and recovery_successes == recovery_attempts
                else "RECOVERY_NOT_NEEDED"
                if recovery_attempts == 0
                and recovery_not_needed == len(results)
                else "NOT_FULLY_EVALUATED"
            ),
            "simulation_note": (
                "Recovery represents a simulated retest with the planned "
                "controls re-enabled, not an actual system repair."
            ),
            "unknown_event_count": unknown_events,
            "fully_evaluated_branches": (
                len(results) - unknown_events
            ),
        }
