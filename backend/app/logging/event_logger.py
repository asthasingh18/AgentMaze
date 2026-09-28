from datetime import datetime


class EventLogger:

    def __init__(self):
        self.events = []

    def log(self, event_type, agent_id, details=None, status="INFO"):

        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "agent_id": agent_id,
            "details": details or {},
            "status": status
        }

        self.events.append(event)

    def get_events(self):
        return self.events

    def log_security_event(self, event_type, agent_id, details=None, severity="MEDIUM"):
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "agent_id": agent_id,
            "details": details or {},
            "severity": severity
        }

        self.events.append(event)

        return event

    def get_security_events(self):

        return [
            event
            for event in self.events
            if "severity" in event
       ]