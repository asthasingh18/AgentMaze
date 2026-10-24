
from app.database import load_attack_events_from_database
from app.security.attack_explorer import AttackExplorer
from app.security.path_risk_scorer import PathRiskScorer


events = load_attack_events_from_database()

# Discover paths from the loaded database events.
class DatabaseEventManager:
    def __init__(self, events):
        self.events = events


explorer = AttackExplorer(DatabaseEventManager(events))
paths = explorer.discover_paths()

scorer = PathRiskScorer()
ranked_paths = scorer.score_and_save_paths(paths)

print("\nRANKED ATTACK PATHS:")

for path in ranked_paths:
    print(
        path["path_id"],
        "| Score:", path["score"],
        "| Risk:", path["risk_level"],
        "| Length:", path["length"],
        "| Events:", " -> ".join(path["events"])
    )

print("\nRisk scoring completed.")
