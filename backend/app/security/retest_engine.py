class RetestEngine:

    def __init__(self):

        self.blocked_controls = set()

    # --------------------------------------------------------
    # APPLY MITIGATION
    # --------------------------------------------------------

    def apply_mitigation(self, mitigation_plan):

        for action in mitigation_plan["actions"]:

            self.blocked_controls.add(
                action["control"]
            )

    # --------------------------------------------------------
    # CONTROL MAPPING
    # --------------------------------------------------------

    def get_required_control(self, event_type):

        control_map = {

            "GOAL_HIJACKING":
                "GOAL_VALIDATION",

            "SESSION_CONTEXT_CONTAMINATION":
                "MEMORY_PROVENANCE_CHECK",

            "INTER_AGENT_TRUST_ESCALATION":
                "CAPABILITY_VERIFICATION",

            "MCP_TOOL_ABUSE":
                "MCP_PROVENANCE_CHECK"
        }

        return control_map.get(event_type)

    # --------------------------------------------------------
    # CHECK WHETHER EVENT IS BLOCKED
    # --------------------------------------------------------

    def is_blocked(self, event_type):

        required_control = self.get_required_control(
            event_type
        )

        return required_control in self.blocked_controls

    # --------------------------------------------------------
    # RE-TEST ATTACK PATH
    # --------------------------------------------------------

    def retest_path(self, path):

        if not path:

            return {
                "status": "PASS",
                "original_length": 0,
                "executed_steps": [],
                "blocked_at": None,
                "message": "No attack path to test."
            }

        executed_steps = []

        for event in path:

            control = self.get_required_control(
                event.event_type
            )

            # ------------------------------------------------
            # MITIGATION BLOCKED THE ATTACK
            # ------------------------------------------------

            if self.is_blocked(event.event_type):

                return {
                    "status": "PASS",
                    "original_length": len(path),
                    "executed_steps": executed_steps,
                    "blocked_at": event.event_type,
                    "blocked_control": control,
                    "message": (
                        f"Attack blocked at "
                        f"{event.event_type}"
                    )
                }

            # ------------------------------------------------
            # ATTACK STEP SUCCESSFULLY EXECUTED
            # ------------------------------------------------

            executed_steps.append({
                "event_id": event.event_id,
                "event_type": event.event_type,
                "agent": event.agent_id,
                "severity": event.severity,
                "status": "EXECUTED"
            })

        # ----------------------------------------------------
        # NO MITIGATION STOPPED THE ATTACK
        # ----------------------------------------------------

        return {
            "status": "FAIL",
            "original_length": len(path),
            "executed_steps": executed_steps,
            "blocked_at": None,
            "blocked_control": None,
            "message": "Attack path remains exploitable."
        }