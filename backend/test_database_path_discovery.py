
from app.security.attack_explorer import AttackExplorer


explorer = AttackExplorer()
paths = explorer.discover_paths()

print("\nDATABASE-BACKED ATTACK PATHS:")

for path in paths:
    print(
        " -> ".join(
            f"{event.event_id}:{event.event_type}"
            for event in path
        )
    )

expected_parent = "ATK-009"
expected_child = "ATK-010"

found = any(
    any(event.event_id == expected_parent for event in path)
    and any(event.event_id == expected_child for event in path)
    for path in paths
)

print("\nExpected parent-child path found:", found)

assert found, "Expected database-backed attack path was not discovered."
print("TEST PASSED")
