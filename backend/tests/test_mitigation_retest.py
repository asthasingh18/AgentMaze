
from app.database import load_attack_events_from_database
from app.security.attack_explorer import AttackExplorer
from app.security.mitigation_engine import MitigationEngine
from app.security.retest_engine import RetestEngine


class DatabaseEventManager:
    def __init__(self, events):
        self.events = events


# 1. Load events and discover paths
events = load_attack_events_from_database()
explorer = AttackExplorer(DatabaseEventManager(events))
paths = explorer.discover_paths()

if not paths:
    print("No attack paths found. Test cannot continue.")
    raise SystemExit(1)

# 2. Select a path containing a supported attack event
mitigation_engine = MitigationEngine()
retest_engine = RetestEngine()

selected_path = next(
    (
        path for path in paths
        if any(
            mitigation_engine.get_mitigation(event.event_type)["control"]
            != "MANUAL_REVIEW"
            for event in path
        )
    ),
    None
)

if selected_path is None:
    print("No path with a predefined mitigation was found.")
    raise SystemExit(1)

print("SELECTED ATTACK PATH:")
print(" -> ".join(event.event_type for event in selected_path))

# 3. Test before mitigation
before = retest_engine.retest_path(selected_path)
print("\nBEFORE MITIGATION:")
print("Status:", before["status"])
print("Executed steps:", len(before["executed_steps"]))
print("Message:", before["message"])

# 4. Generate and apply the mitigation plan
plan = mitigation_engine.generate_plan(selected_path)
print("\nMITIGATION PLAN:")
for action in plan["actions"]:
    print("-", action["event"], "->", action["control"])
    print(" ", action["action"])

retest_engine.apply_mitigation(plan)

# 5. Re-test the same path
after = retest_engine.retest_path(selected_path)
print("\nAFTER MITIGATION:")
print("Status:", after["status"])
print("Executed steps:", len(after["executed_steps"]))
print("Blocked at:", after["blocked_at"])
print("Blocked control:", after.get("blocked_control"))
print("Message:", after["message"])

print("\nMITIGATION RETEST COMPLETED")
