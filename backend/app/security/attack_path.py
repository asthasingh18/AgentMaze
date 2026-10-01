class AttackPath:

    def __init__(self, path_id):

        self.path_id = path_id
        self.events = []

    def add_event(self, event):

        self.events.append(event)

    def get_path(self):

        return [
            event.to_dict()
            for event in self.events
        ]

    def length(self):

        return len(self.events)

    def get_sequence(self):

        return [
            event.event_type
            for event in self.events
        ]