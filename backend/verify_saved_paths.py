
from app.database import get_saved_attack_paths

paths = get_saved_attack_paths()

print("Paths retrieved from SQLite:", len(paths))

for path in paths:
    print(
        path["path_id"],
        "->",
        " -> ".join(
            event["event_type"]
            for event in path["events"]
        )
    )

assert len(paths) >= 7, "Expected saved paths were not found."

assert any(
    any(
        event["event_type"] == "GOAL_HIJACKING"
        for event in path["events"]
    )
    and any(
        event["event_type"] == "INTER_AGENT_TRUST_ESCALATION"
        for event in path["events"]
    )
    for path in paths
), "Expected multi-event path was not persisted."

print("\nPERSISTENCE TEST PASSED")
