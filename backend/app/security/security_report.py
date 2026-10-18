
from app.security.path_risk_scorer import PathRiskScorer
from app.security.path_explainer import PathExplainer
from app.security.mitigation_engine import MitigationEngine
from app.security.retest_engine import RetestEngine
from app.security.security_analytics import SecurityAnalytics


class SecurityReport:

    def __init__(self):
        self.risk_scorer = PathRiskScorer()
        self.path_explainer = PathExplainer()
        self.mitigation_engine = MitigationEngine()
        self.retest_engine = RetestEngine()
        self.security_analytics = SecurityAnalytics()

    def generate_report(self, path):

        if not path:
            return {
                "status": "NO_PATH",
                "message": "No attack path is available.",
                "risk": None,
                "explanation": None,
                "mitigation_plan": None,
                "retest": None
            }

        risk = self.risk_scorer.score_path(path)
        explanation = self.path_explainer.explain_path(path)
        mitigation_plan = self.mitigation_engine.generate_plan(path)

        before_retest = RetestEngine().retest_path(path)

        self.retest_engine.apply_mitigation(mitigation_plan)
        after_retest = self.retest_engine.retest_path(path)

        return {
            "status": "GENERATED",
            "path": [
                {
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "agent_id": event.agent_id,
                    "severity": event.severity
                }
                for event in path
            ],
            "risk": risk,
            "explanation": explanation,
            "mitigation_plan": mitigation_plan,
            "before_retest": before_retest,
            "after_retest": after_retest
        }

    def generate_branch_report(self, paths):

        if not paths:
            return {
                "status": "NO_PATHS",
                "branches": [],
                "overall_status": "NOT_TESTED",
                "effectiveness_percentage": 0
            }

        branches = []

        for index, path in enumerate(paths, start=1):
            risk = self.risk_scorer.score_path(path)
            mitigation_plan = self.mitigation_engine.generate_plan(path)
            before_retest = RetestEngine().retest_path(path)

            branch_retest_engine = RetestEngine()
            branch_retest_engine.apply_mitigation(mitigation_plan)
            after_retest = branch_retest_engine.retest_path(path)

            blocked = after_retest["status"] == "PASS"

            branch_effectiveness = {
                "blocked": blocked,
                "blocked_at": after_retest.get("blocked_at"),
                "blocked_control": after_retest.get("blocked_control"),
                "effectiveness": (
                    "EFFECTIVE" if blocked else "INEFFECTIVE"
                )
            }

            branches.append({
                "branch": index,
                "attack_sequence": [
                    event.event_type for event in path
                ],
                "path_length": len(path),
                "risk": risk,
                "mitigation_plan": mitigation_plan,
                "before_retest": before_retest,
                "after_retest": after_retest,
                "mitigation_effectiveness": branch_effectiveness
            })

        effective_count = sum(
            1 for branch in branches
            if branch["mitigation_effectiveness"]["blocked"]
        )

        effectiveness_percentage = round(
            (effective_count / len(branches)) * 100, 2
        )

        return {
            "status": "GENERATED",
            "branch_count": len(branches),
            "branches": branches,
            "effective_branches": effective_count,
            "ineffective_branches": len(branches) - effective_count,
            "effectiveness_percentage": effectiveness_percentage,
            "overall_status": (
                "PASS" if effective_count == len(branches) else "FAIL"
            )
        }

    def generate_adaptive_report(self, paths, disabled_controls=None):

        if not paths:
            return {
                "status": "NO_PATHS",
                "branches": [],
                "overall_status": "NOT_TESTED",
                "effectiveness_percentage": 0
            }

        if disabled_controls is None:
            disabled_controls = {"GOAL_VALIDATION"}
        else:
            disabled_controls = set(disabled_controls)

        branches = []

        for index, path in enumerate(paths, start=1):
            mitigation_plan = self.mitigation_engine.generate_plan(path)

            adaptive_engine = RetestEngine()
            adaptive_engine.apply_mitigation(mitigation_plan)

            result = adaptive_engine.retest_path_with_disabled_controls(
                path, disabled_controls
            )

            blocked = result["status"] == "PASS"

            branches.append({
                "branch": index,
                "attack_sequence": [
                    event.event_type for event in path
                ],
                "disabled_controls": sorted(disabled_controls),
                "executed_steps": result["executed_steps"],
                "blocked_at": result.get("blocked_at"),
                "blocked_control": result.get("blocked_control"),
                "remaining_exploitable": not blocked,
                "status": result["status"],
                "message": result["message"]
            })

        effective_count = sum(
            1 for branch in branches
            if branch["status"] == "PASS"
        )

        total = len(branches)
        effectiveness_percentage = round(
            effective_count / total * 100, 2
        )

        return {
            "status": "GENERATED",
            "disabled_controls": sorted(disabled_controls),
            "branch_count": total,
            "branches": branches,
            "effective_branches": effective_count,
            "ineffective_branches": total - effective_count,
            "effectiveness_percentage": effectiveness_percentage,
            "overall_status": (
                "PASS" if effective_count == total else "FAIL"
            )
        }

    def generate_analytics_report(self, paths):
        return self.security_analytics.generate_summary(paths)
