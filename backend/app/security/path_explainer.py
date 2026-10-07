class PathExplainer:

    def explain_path(self, path):

        if not path:
            return {
                "summary": "No attack path was provided.",
                "steps": [],
                "root_cause": None,
                "terminal_event": None
            }

        steps = []

        for index, event in enumerate(path, start=1):

            step = {
                "step": index,
                "event_id": event.event_id,
                "event_type": event.event_type,
                "agent": event.agent_id,
                "severity": event.severity,
                "description": event.description,
                "source": event.source,
                "target": event.target,
                "relation": event.relation
            }

            steps.append(step)

        root_event = path[0]
        terminal_event = path[-1]

        summary = (
            f"The attack path contains {len(path)} steps, "
            f"starting with {root_event.event_type} "
            f"and ending with {terminal_event.event_type}."
        )

        return {
            "summary": summary,
            "steps": steps,
            "root_cause": {
                "event_id": root_event.event_id,
                "event_type": root_event.event_type,
                "description": root_event.description
            },
            "terminal_event": {
                "event_id": terminal_event.event_id,
                "event_type": terminal_event.event_type,
                "description": terminal_event.description
            }
        }