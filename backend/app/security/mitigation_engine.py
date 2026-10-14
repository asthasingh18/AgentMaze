class MitigationEngine:

    def __init__(self):

        self.mitigations = {
            "GOAL_HIJACKING": {
                "action": "Validate instructions against the original agent goal",
                "control": "GOAL_VALIDATION"
            },

            "SESSION_CONTEXT_CONTAMINATION": {
                "action": "Reject or isolate untrusted memory from trusted context",
                "control": "MEMORY_PROVENANCE_CHECK"
            },

            "INTER_AGENT_TRUST_ESCALATION": {
                "action": "Verify target agent capabilities before delegation",
                "control": "CAPABILITY_VERIFICATION"
            },

            "MCP_TOOL_ABUSE": {
                "action": "Validate tool provenance and isolate untrusted tool instructions",
                "control": "MCP_PROVENANCE_CHECK"
            },

            "MCP_PLUGIN_ABUSE": {
                "action": "Validate tool permissions and verify tool provenance before execution",
                "control": "MCP_PROVENANCE_CHECK"
            },

            "CAPABILITY_ABUSE": {
                "action": "Enforce least-privilege permissions and verify capabilities before each sensitive operation",
                "control": "CAPABILITY_ENFORCEMENT"
            }


        }

    def get_mitigation(self, event_type):

        return self.mitigations.get(
            event_type,
            {
                "action": "No predefined mitigation available",
                "control": "MANUAL_REVIEW"
            }
        )

    def generate_plan(self, path):

        if not path:
            return {
                "controls": [],
                "actions": []
            }

        controls = []
        actions = []

        for event in path:

            mitigation = self.get_mitigation(
                event.event_type
            )

            controls.append(
                mitigation["control"]
            )

            actions.append({
                "event": event.event_type,
                "control": mitigation["control"],
                "action": mitigation["action"]
            })

        return {
            "controls": list(dict.fromkeys(controls)),
            "actions": actions
        }

    def generate_plan_for_paths(self, paths):

        if not paths:
            return {
                "controls": [],
                "actions": []
            }

        controls = []
        actions = []
        processed_events = set()

        for path in paths:
            for event in path:

                # Avoid duplicate actions for shared events.
                event_key = (
                    event.event_id
                    if event.event_id is not None
                    else (event.event_type, event.agent_id)
                )

                if event_key in processed_events:
                    continue

                processed_events.add(event_key)

                mitigation = self.get_mitigation(
                    event.event_type
                )

                control = mitigation["control"]

                controls.append(control)

                actions.append({
                    "event": event.event_type,
                    "control": control,
                    "action": mitigation["action"]
                })

        return {
            "controls": list(dict.fromkeys(controls)),
            "actions": actions
        }    