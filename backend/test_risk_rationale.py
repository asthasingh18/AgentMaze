
from app.database import load_attack_events_from_database
from app.security.attack_explorer import AttackExplorer
from app.security.path_explainer import PathExplainer


class DatabaseEventManager:
    def __init__(self, events):
        self.events = events


events = load_attack_events_from_database()
paths = AttackExplorer(DatabaseEventManager(events)).discover_paths()
explainer = PathExplainer()

for path in paths:
    result = explainer.explain_path(path)

    print("\nPath:", " -> ".join(
        event.event_type for event in path
    ))
    print("Summary:", result["summary"])

    print("Risk rationale:")
    for item in result["risk_rationale"]:
        print("-", item["reason"])

print("\nRISK RATIONALE TEST COMPLETED")
