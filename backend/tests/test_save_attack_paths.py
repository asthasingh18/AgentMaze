
from app.security.attack_explorer import AttackExplorer
from app.database import save_attack_path, get_saved_attack_paths


explorer = AttackExplorer()
discovered_paths = explorer.discover_paths()

print("Discovered paths:", len(discovered_paths))

for index, events in enumerate(discovered_paths, start=1):
    path_id = f"DB-PATH-{index:03d}"

    save_attack_path(
        path_id=path_id,
        events=events,
        risk_level="PENDING",
        description="Risk assessment not yet calculated"
    )

saved_paths = get_saved_attack_paths()

print("\nSAVED ATTACK PATHS:")

for path in saved_paths:
    print(path["path_id"], "Events:", [
        event["event_type"] for event in path["events"]
    ])

print("\nTotal saved paths:", len(saved_paths))
