
from app.security.attack_manager import AttackManager
from app.security.attack_explorer import AttackExplorer
from app.security.attack_path_manager import AttackPathManager


manager = AttackManager()

parent = manager.record_event(
    event_type="TEST_PARENT",
    agent_id="A001",
    description="Test starting event",
    severity="HIGH"
)

child = manager.record_event(
    event_type="TEST_CHILD",
    agent_id="A002",
    description="Test dependent event",
    severity="HIGH",
    parent_event_ids=[parent.event_id],
    relation="leads_to"
)

explorer = AttackExplorer(manager)
event_sequences = explorer.discover_paths()

path_manager = AttackPathManager()
path_manager.create_paths_from_events(event_sequences)

print("ATTACK PATHS:")

for path in path_manager.get_paths():
    print(path["path_id"], "Length:", path["length"])
    print("Events:", [
        event["event_type"]
        for event in path["events"]
    ])
