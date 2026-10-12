
class PathExplainer:

    EVENT_RATIONALES = {
        "MCP_PLUGIN_ABUSE": (
            "An agent attempted to use a tool it was not authorized to access."
        ),
        "CAPABILITY_ABUSE": (
            "An agent attempted an operation without the required capability."
        ),
        "GOAL_HIJACKING": (
            "An agent's intended objective may have been redirected or manipulated."
        ),
        "INTER_AGENT_TRUST_ESCALATION": (
            "Trust between agents may have allowed an unsafe action or request "
            "to propagate across an agent boundary."
        ),
        "SESSION_CONTEXT_CONTAMINATION": (
            "Untrusted or manipulated context may have influenced subsequent "
            "agent behavior."
        )
    }

    def explain_path(self, path):

        if not path:
            return {
                "summary": "No attack path was provided.",
                "steps": [],
                "root_cause": None,
                "terminal_event": None,
                "risk_rationale": []
            }

        steps = []
        risk_rationale = []

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

            rationale = self.EVENT_RATIONALES.get(
                event.event_type,
                "This event was recorded in the attack path. "
                "Its security impact requires further investigation."
            )

            risk_rationale.append({
                "event_id": event.event_id,
                "event_type": event.event_type,
                "severity": event.severity,
                "reason": rationale
            })

        root_event = path[0]
        terminal_event = path[-1]

        summary = (
            f"The attack path contains {len(path)} step(s), "
            f"starting with {root_event.event_type} "
            f"and ending with {terminal_event.event_type}."
        )

        if len(path) > 1:
            chain_explanation = (
                f"The path connects {len(path)} recorded events. "
                "Review the dependency between consecutive events to "
                "determine whether the earlier event contributed to the later one."
            )
        else:
            chain_explanation = (
                "This is a standalone event; no linked follow-on event "
                "was found in this path."
            )

        risk_rationale.append({
            "event_id": None,
            "event_type": "PATH_ANALYSIS",
            "severity": None,
            "reason": chain_explanation
        })

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
            },
            "risk_rationale": risk_rationale
        }
