
from app.database import load_attack_events_from_database
from app.security.attack_explorer import AttackExplorer
from app.security.path_explainer import PathExplainer


class DatabaseEventManager:
    def __init__(self, events):
        self.events = events


events = load_attack_events_from_database()
explorer = AttackExplorer(DatabaseEventManager(events))
paths = explorer.discover_paths()

explainer = PathExplainer()

print("\nATTACK PATH EXPLANATIONS")

for path in paths:
    explanation = explainer.explain_path(path)

    print("\n" + "=" * 55)
    print("Path:", " -> ".join(
        event.event_type for event in path
    ))

    print("\nSummary:")
    print(explanation["summary"])

    print("\nRoot Cause:")
    print(explanation["root_cause"])

    print("\nAttack Steps:")

    for step in explanation["steps"]:
        print(
            f'{step["step"]}. {step["event_type"]} '
            f'| Agent: {step["agent"]} '
            f'| Severity: {step["severity"]}'
        )
        print("   ", step["description"])

    print("\nTerminal Event:")
    print(explanation["terminal_event"])

print("\nPATH EXPLANATION TEST COMPLETED")
