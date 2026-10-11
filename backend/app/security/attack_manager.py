from app.database import save_attack_event , save_event_dependency
from app.security.attack_event import AttackEvent



class AttackManager:

    def __init__(self):

        self.events = []
        self.next_event_id = self._get_next_event_id()

    def _get_next_event_id(self):

        from app.database import get_connection

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute("""
            SELECT event_id
            FROM attack_events
            WHERE event_id LIKE 'ATK-%'
        """)

        rows = cursor.fetchall()
        connection.close()

        existing_ids = []

        for row in rows:
            try:
                number = int(row[0].split("-")[1])
                existing_ids.append(number)
            except (ValueError, IndexError):
                continue

        return max(existing_ids, default=0) + 1
    

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

        if parent_event_ids:
            for parent_event_id in parent_event_ids:
                save_event_dependency(
                    parent_event_id=parent_event_id,
                    child_event_id=event.event_id,
                    relation=relation or "leads_to"
                )

        return event


    def get_events(self):

        return [
            event.to_dict()
            for event in self.events
        ]