class AttackExplorer:

    def __init__(self, attack_manager):

        self.attack_manager = attack_manager

    def get_events(self):

        return self.attack_manager.events

    def discover_paths(self):

        events = self.get_events()

        event_map = {
            event.event_id: event
            for event in events
        }

        paths = []

        for event in events:

            # Events without parents are possible
            # starting points of attack paths.
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

        # Find every event that depends on
        # the current event.
        for candidate in event_map.values():

            if current_event.event_id in candidate.parent_event_ids:

                children.append(candidate)

        # No children means this is a terminal path.
        if not children:

            paths.append(current_path)

            return

        # Explore EVERY child.
        for child in children:

            new_path = current_path + [child]

            self._explore_paths(
                child,
                event_map,
                new_path,
                paths
            )

    def get_path_sequences(self):

        paths = self.discover_paths()

        return [
            [
                event.event_type
                for event in path
            ]
            for path in paths
        ]