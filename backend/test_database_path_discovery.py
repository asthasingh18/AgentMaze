
from app.security.attack_event import AttackEvent
from app.security.attack_explorer import AttackExplorer


class TestEventManager:
    """Provides controlled events without using the project database."""

    def __init__(self, events):
        self.events = events


def main():
    # Create a controlled parent event.
    parent = AttackEvent(
        event_type="TEST_PARENT",
        agent_id="TEST-A01",
        description="Test starting event",
        severity="HIGH",
    )
    parent.event_id = "TEST-PARENT-001"

    # Create a child event linked to the parent.
    child = AttackEvent(
        event_type="TEST_CHILD",
        agent_id="TEST-A02",
        description="Test dependent event",
        severity="HIGH",
        parent_event_ids=[parent.event_id],
        relation="leads_to",
    )
    child.event_id = "TEST-CHILD-001"

    manager = TestEventManager([parent, child])
    explorer = AttackExplorer(manager)

    paths = explorer.discover_paths()

    print("\nTEST ATTACK PATHS:")
    for path in paths:
        print(" -> ".join(event.event_type for event in path))

    expected_path = ["TEST_PARENT", "TEST_CHILD"]

    found = any(
        [event.event_type for event in path] == expected_path
        for path in paths
    )

    print("\nExpected parent-child path found:", found)
    assert found, "Expected parent-child attack path was not discovered."

    print("TEST PASSED")


if __name__ == "__main__":
    main()
