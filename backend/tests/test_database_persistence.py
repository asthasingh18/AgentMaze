
import os
import tempfile

import app.database as database
from app.security.attack_event import AttackEvent
from app.security.attack_explorer import AttackExplorer


class TestEventManager:
    def __init__(self, events):
        self.events = events


def main():
    original_database_path = database.DATABASE_PATH

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            test_db_path = os.path.join(temp_dir, "agentmaze_test.db")
            database.DATABASE_PATH = test_db_path

            # Create an isolated database with the project schema.
            database.create_tables()

            # Insert agents required by the attack_events foreign key.
            connection = database.get_connection()
            connection.executemany(
                """
                INSERT INTO agents (agent_id, name)
                VALUES (?, ?)
                """,
                [
                    ("TEST-A01", "Persistence Test Agent A"),
                    ("TEST-A02", "Persistence Test Agent B"),
                ],
            )
            connection.commit()
            connection.close()

            # Create two related attack events.
            parent = AttackEvent(
                event_type="TEST_PARENT",
                agent_id="TEST-A01",
                description="Test starting event",
                severity="HIGH",
            )
            parent.event_id = "TEST-PARENT-001"

            child = AttackEvent(
                event_type="TEST_CHILD",
                agent_id="TEST-A02",
                description="Test dependent event",
                severity="HIGH",
                parent_event_ids=[parent.event_id],
                relation="leads_to",
            )
            child.event_id = "TEST-CHILD-001"

            # Persist both events and their dependency.
            database.save_attack_event(parent)
            database.save_attack_event(child)
            database.save_event_dependency(
                parent.event_id,
                child.event_id,
                "leads_to",
            )

            # Reload events from the temporary database.
            loaded_events = database.load_attack_events_from_database()
            loaded_by_id = {
                event.event_id: event for event in loaded_events
            }

            assert parent.event_id in loaded_by_id
            assert child.event_id in loaded_by_id

            loaded_child = loaded_by_id[child.event_id]
            assert parent.event_id in loaded_child.parent_event_ids

            # Confirm the reloaded relationship forms an attack path.
            explorer = AttackExplorer(TestEventManager(loaded_events))
            paths = explorer.discover_paths()

            expected_path = ["TEST_PARENT", "TEST_CHILD"]
            found = any(
                [event.event_type for event in path] == expected_path
                for path in paths
            )

            assert found, "Reloaded parent-child path was not discovered."

            print("Events saved and reloaded: PASS")
            print("Parent-child relationship restored: PASS")
            print("Attack path discovered after reload: PASS")
            print("DATABASE PERSISTENCE TEST PASSED")

    finally:
        database.DATABASE_PATH = original_database_path


if __name__ == "__main__":
    main()
