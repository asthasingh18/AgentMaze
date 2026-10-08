from app.database import save_attack_event
from app.security.attack_event import AttackEvent



class AttackManager:

    def __init__(self):

        self.events = []
        self.next_event_id = 1

    def record_event(
        self,
        event_type,
        agent_id,
        description,
        severity="MEDIUM",
        source=None,
        target=None,
        parent_event_ids=None,
        relation=None
    ):

        event = AttackEvent(
            event_type=event_type,
            agent_id=agent_id,
            description=description,
            severity=severity,
            source=source,
            target=target,
            parent_event_ids=parent_event_ids,
            relation=relation
        )

        event.event_id = f"ATK-{self.next_event_id:03d}"

        self.next_event_id += 1

        self.events.append(event)

        save_attack_event(event)

        return event

    def get_events(self):

        return [
            event.to_dict()
            for event in self.events
        ]