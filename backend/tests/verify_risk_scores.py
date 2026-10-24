
from app.database import get_saved_attack_paths

paths = get_saved_attack_paths()

print("\nSAVED PATH RISK SCORES:")

for path in paths:
    print(
        path["path_id"],
        "| Risk:", path["risk_level"],
        "| Description:", path["description"]
    )

assert paths, "No saved attack paths found."

assert all(
    path["risk_level"] not in (None, "", "PENDING")
    for path in paths
), "Some paths still have pending risk levels."

print("\nRISK PERSISTENCE TEST PASSED")
