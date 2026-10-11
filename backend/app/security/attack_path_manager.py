
from app.security.attack_path import AttackPath


class AttackPathManager:

    def __init__(self):

        self.paths = []
        self.next_path_id = 1

    def create_path(self):

        path = AttackPath(
            path_id=f"PATH-{self.next_path_id:03d}"
        )

        self.next_path_id += 1
        self.paths.append(path)

        return path

    def add_event_to_path(self, path, event):

        path.add_event(event)

    def create_paths_from_events(self, event_sequences):

        created_paths = []

        for event_sequence in event_sequences:

            if not event_sequence:
                continue

            path = self.create_path()

            for event in event_sequence:
                self.add_event_to_path(path, event)

            created_paths.append(path)

        return created_paths

    def get_paths(self):

        return [
            {
                "path_id": path.path_id,
                "length": path.length(),
                "events": path.get_path()
            }
            for path in self.paths
        ]