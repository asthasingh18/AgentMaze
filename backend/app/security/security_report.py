
from app.security.path_risk_scorer import PathRiskScorer
from app.security.path_explainer import PathExplainer
from app.security.mitigation_engine import MitigationEngine
from app.security.retest_engine import RetestEngine


class SecurityReport:

    def __init__(self):
        self.risk_scorer = PathRiskScorer()
        self.path_explainer = PathExplainer()
        self.mitigation_engine = MitigationEngine()
        self.retest_engine = RetestEngine()

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

        # 1. Assess risk
        risk = self.risk_scorer.score_path(path)

        # 2. Explain the path
        explanation = self.path_explainer.explain_path(path)

        # 3. Generate mitigation recommendations
        mitigation_plan = self.mitigation_engine.generate_plan(path)

        # 4. Test before mitigation
        before_retest = RetestEngine().retest_path(path)

        # 5. Apply controls and re-test
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
                "overall_status": "NOT_TESTED"
            }

        branches = []

        for index, path in enumerate(paths, start=1):

            # Assess the individual branch.
            risk = self.risk_scorer.score_path(path)

            # Recommend controls for this branch only.
            mitigation_plan = self.mitigation_engine.generate_plan(path)

            # Check the path before mitigation.
            before_retest = RetestEngine().retest_path(path)

            # Use a fresh engine so controls from one branch
            # cannot accidentally affect another branch.
            branch_retest_engine = RetestEngine()
            branch_retest_engine.apply_mitigation(mitigation_plan)

            after_retest = branch_retest_engine.retest_path(path)

            branches.append({
                "branch": index,
                "attack_sequence": [
                    event.event_type for event in path
                ],
                "path_length": len(path),
                "risk": risk,
                "mitigation_plan": mitigation_plan,
                "before_retest": before_retest,
                "after_retest": after_retest
            })

        all_passed = all(
            branch["after_retest"]["status"] == "PASS"
            for branch in branches
        )

        return {
            "status": "GENERATED",
            "branch_count": len(branches),
            "branches": branches,
            "overall_status": "PASS" if all_passed else "FAIL"
        }
    
