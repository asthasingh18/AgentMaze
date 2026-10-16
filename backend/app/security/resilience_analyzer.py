
from app.security.mitigation_engine import MitigationEngine
from app.security.retest_engine import RetestEngine


class ResilienceAnalyzer:

    def __init__(self):
        self.mitigation_engine = MitigationEngine()

    def analyze(self, paths, failure_scenarios=None):

        if not paths:
            return {
                "status": "NO_PATHS",
                "scenario_count": 0,
                "results": [],
                "vulnerable_branches": [],
                "overall_status": "NOT_TESTED"
            }

        # Default scenarios based on our recent experiments.
        if failure_scenarios is None:
            failure_scenarios = [
                set(),
                {"GOAL_VALIDATION"},
                {"GOAL_VALIDATION", "MEMORY_PROVENANCE_CHECK"},
                {"GOAL_VALIDATION", "MCP_PROVENANCE_CHECK"},
                {
                    "GOAL_VALIDATION",
                    "MEMORY_PROVENANCE_CHECK",
                    "CAPABILITY_VERIFICATION",
                    "MCP_PROVENANCE_CHECK"
                }
            ]

        results = []

        for scenario_index, disabled_controls in enumerate(
            failure_scenarios, start=1
        ):
            scenario_results = []

            for branch_index, path in enumerate(paths, start=1):

                plan = self.mitigation_engine.generate_plan(path)

                engine = RetestEngine()
                engine.apply_mitigation(plan)

                retest = engine.retest_path_with_disabled_controls(
                    path,
                    disabled_controls
                )

                scenario_results.append({
                    "branch": branch_index,
                    "attack_sequence": [
                        event.event_type for event in path
                    ],
                    "status": retest["status"],
                    "blocked_at": retest.get("blocked_at"),
                    "blocked_control": retest.get("blocked_control"),
                    "executed_steps": retest["executed_steps"],
                    "remaining_exploitable": retest["status"] == "FAIL"
                })

            results.append({
                "scenario": scenario_index,
                "disabled_controls": sorted(disabled_controls),
                "branch_results": scenario_results,
                "vulnerable_branch_count": sum(
                    item["remaining_exploitable"]
                    for item in scenario_results
                )
            })

        vulnerable_branches = []

        for branch_index, path in enumerate(paths, start=1):
            vulnerable_scenarios = [
                result["scenario"]
                for result in results
                if any(
                    branch["branch"] == branch_index
                    and branch["remaining_exploitable"]
                    for branch in result["branch_results"]
                )
            ]

            if vulnerable_scenarios:
                vulnerable_branches.append({
                    "branch": branch_index,
                    "attack_sequence": [
                        event.event_type for event in path
                    ],
                    "vulnerable_scenarios": vulnerable_scenarios,
                    "vulnerability_count": len(vulnerable_scenarios)
                })

        total_tests = len(results) * len(paths)
        vulnerable_tests = sum(
            result["vulnerable_branch_count"] for result in results
        )
        
        
        blocked_tests = total_tests - vulnerable_tests
        scenario_summary = [
            {
                "scenario": result["scenario"],
                "disabled_controls": result["disabled_controls"],
                "vulnerable_branch_count": result["vulnerable_branch_count"],
                "total_branches": len(paths),
                "resilience_percentage": round(
                    (
                        (len(paths) - result["vulnerable_branch_count"])
                        / len(paths)
                    ) * 100,
                    2
                ) if paths else 0
            }
            for result in results
        ]

        return {
            "status": "GENERATED",
            "scenario_count": len(results),
            "branch_count": len(paths),
            "total_tests": total_tests,
            "blocked_tests": blocked_tests,
            "vulnerable_tests": vulnerable_tests,
            "resilience_percentage": round(
                (blocked_tests / total_tests) * 100, 2
            ) if total_tests else 0,
            "results": results,
            "scenario_summary": scenario_summary,
            "vulnerable_branches": vulnerable_branches,
            "overall_status": (
                "VULNERABLE" if vulnerable_tests else "RESILIENT"
            )
        }

