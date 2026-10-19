
from collections import Counter

from app.security.path_risk_scorer import PathRiskScorer
from app.security.retest_engine import RetestEngine
from app.security.mitigation_engine import MitigationEngine


class SecurityAnalytics:

    def __init__(self):
        self.risk_scorer = PathRiskScorer()
        self.mitigation_engine = MitigationEngine()

    def generate_summary(self, paths):

        if not paths:
            return {
                "status": "NO_PATHS",
                "path_count": 0,
                "risk_distribution": {
                    "LOW": 0,
                    "MEDIUM": 0,
                    "HIGH": 0,
                    "CRITICAL": 0
                },
                "average_risk_score": 0,
                "event_frequency": {},
                "blocked_paths": 0,
                "exploitable_paths": 0,
                "blocking_percentage": 0,
                "potential_control_weaknesses": {}
            }

        risk_distribution = {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0
        }

        event_counter = Counter()
        scores = []
        blocked_paths = 0
        exploitable_paths = 0
        manual_review_paths = 0
        control_failure_counter = Counter()

        for path in paths:

            risk = self.risk_scorer.score_path(path)
            scores.append(risk["score"])
            risk_distribution[risk["risk_level"]] += 1

            for event in path:
                event_counter[event.event_type] += 1

            mitigation_plan = self.mitigation_engine.generate_plan(path)

            retest_engine = RetestEngine()
            retest_engine.apply_mitigation(mitigation_plan)
            result = retest_engine.retest_path(path)

            if result["status"] == "PASS":
                blocked_paths += 1

            elif result["status"] == "UNKNOWN_EVENT":
                manual_review_paths += 1

            else:
                exploitable_paths += 1

                # Record required controls for recognized events in failed paths.
                for event in path:
                    control = retest_engine.get_required_control(
                        event.event_type
                    )

                    if control:
                        control_failure_counter[control] += 1
        path_count = len(paths)
        blocking_percentage = round(
            (blocked_paths / path_count) * 100, 2
        )

        return {
            "status": "GENERATED",
            "path_count": path_count,
            "risk_distribution": risk_distribution,
            "average_risk_score": round(
                sum(scores) / len(scores), 2
            ),
            "event_frequency": dict(
                sorted(event_counter.items())
            ),
            "blocked_paths": blocked_paths,
            "exploitable_paths": exploitable_paths,
            "blocking_percentage": blocking_percentage,
            "potential_control_weaknesses": dict(
                sorted(control_failure_counter.items())
            ),
            "manual_review_paths": manual_review_paths,
            "evaluated_paths": blocked_paths + exploitable_paths    
        }
