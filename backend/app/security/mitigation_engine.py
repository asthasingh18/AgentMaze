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