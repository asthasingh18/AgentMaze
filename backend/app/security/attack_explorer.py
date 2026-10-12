
from app.database import load_attack_events_from_database


class AttackExplorer:

    def __init__(self, attack_manager=None):
        self.attack_manager = attack_manager

    def get_events(self):
        if self.attack_manager is not None:
            return self.attack_manager.events

        return load_attack_events_from_database()

    def discover_paths(self):
        events = self.get_events()

        event_map = {
            event.event_id: event
            for event in events
        }

        paths = []

        for event in events:
            # Events without parents are starting points.
            if not event.parent_event_ids:
                self._explore_paths(
                    event,
                    event_map,
                    [event],
                    paths
                )

        return paths

    def _explore_paths(
        self,
        current_event,
        event_map,
        current_path,
        paths
    ):
        children = []

        for candidate in event_map.values():
            if current_event.event_id in candidate.parent_event_ids:
                children.append(candidate)

        if not children:
            paths.append(current_path)
            return

        for child in children:
            # Prevent a cycle from causing infinite recursion.
            if child in current_path:
                continue

            self._explore_paths(
                child,
                event_map,
                current_path + [child],
                paths
            )

    def get_path_sequences(self):
        return [
            [event.event_type for event in path]
            for path in self.discover_paths()
        ]
