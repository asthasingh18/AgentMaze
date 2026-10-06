class PathRiskScorer:

    def __init__(self):

        self.severity_weights = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }

    def calculate_score(self, path):

        if not path:
            return 0

        score = 0

        # Score every event in the attack path.
        for event in path:

            score += self.severity_weights.get(
                event.severity,
                1
            )

        # Longer attack chains indicate
        # greater attack complexity.
        if len(path) >= 3:
            score += 2

        if len(path) >= 5:
            score += 3

        return score

    def get_risk_level(self, score):

        if score >= 12:
            return "CRITICAL"

        if score >= 8:
            return "HIGH"

        if score >= 4:
            return "MEDIUM"

        return "LOW"

    def score_path(self, path):

        score = self.calculate_score(path)

        return {
            "score": score,
            "risk_level": self.get_risk_level(score),
            "length": len(path)
        }

    def rank_paths(self, paths):

        ranked_paths = []

        for index, path in enumerate(paths, start=1):

            risk = self.score_path(path)

            ranked_paths.append({
                "path_number": index,
                "path": [
                    event.event_type
                    for event in path
                ],
                "score": risk["score"],
                "risk_level": risk["risk_level"],
                "length": risk["length"]
            })

        ranked_paths.sort(
            key=lambda item: item["score"],
            reverse=True
        )

        return ranked_paths    