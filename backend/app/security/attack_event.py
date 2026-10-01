from datetime import datetime


class AttackEvent:

    def __init__(
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

        self.event_id = None
        self.timestamp = datetime.now().isoformat()
        self.event_type = event_type
        self.agent_id = agent_id
        self.description = description
        self.severity = severity
        self.source = source
        self.target = target
        self.parent_event_ids = parent_event_ids or []
        self.relation = relation

    def to_dict(self):

        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "agent_id": self.agent_id,
            "description": self.description,
            "severity": self.severity,
            "source": self.source,
            "target": self.target,
            "parent_event_ids": self.parent_event_ids,
            "relation": self.relation
        }