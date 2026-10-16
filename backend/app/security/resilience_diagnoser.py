
class ResilienceDiagnoser:
    """Diagnose vulnerable branches from simulated resilience results."""

    CONTROL_DETAILS = {
        "GOAL_VALIDATION": {
            "priority": 1,
            "purpose": "Validate instructions against the agent's original goal.",
        },
        "MEMORY_PROVENANCE_CHECK": {
            "priority": 2,
            "purpose": "Separate untrusted memory from trusted context.",
        },
        "MCP_PROVENANCE_CHECK": {
            "priority": 2,
            "purpose": "Validate tool provenance before tool execution.",
        },
        "CAPABILITY_VERIFICATION": {
            "priority": 3,
            "purpose": "Verify agent capabilities before delegation.",
        },
    }

    EVENT_DETAILS = {
        "GOAL_HIJACKING": (
            "Untrusted input may have redirected the agent from its original goal."
        ),
        "SESSION_CONTEXT_CONTAMINATION": (
            "Untrusted context may have influenced the agent's decisions."
        ),
        "INTER_AGENT_TRUST_ESCALATION": (
            "The agent-to-agent trust boundary may have been crossed without "
            "sufficient verification."
        ),
        "MCP_TOOL_ABUSE": (
            "A tool action may have bypassed expected provenance or "
            "authorization checks."
        ),
    }

    def diagnose(self, resilience_report):
        if resilience_report.get("status") == "NO_PATHS":
            return {
                "status": "NOT_TESTED",
                "diagnosis_count": 0,
                "diagnoses": [],
                "recommendations": [],
                "message": "No attack paths were available for diagnosis.",
            }

        results = resilience_report.get("results", [])
        vulnerable_branches = resilience_report.get(
            "vulnerable_branches", []
        )

        diagnoses = []
        observed_controls = set()

        for vulnerable_branch in vulnerable_branches:
            branch_number = vulnerable_branch["branch"]
            attack_sequence = vulnerable_branch["attack_sequence"]
            vulnerable_scenarios = vulnerable_branch[
                "vulnerable_scenarios"
            ]

            scenario_details = []

            for scenario in results:
                if scenario["scenario"] not in vulnerable_scenarios:
                    continue

                branch_result = next(
                    (
                        item
                        for item in scenario.get("branch_results", [])
                        if item["branch"] == branch_number
                    ),
                    None,
                )

                if branch_result is None:
                    continue

                disabled_controls = scenario.get("disabled_controls", [])
                observed_controls.update(disabled_controls)

                executed_steps = branch_result.get("executed_steps", [])

                scenario_details.append({
                    "scenario": scenario["scenario"],
                    "disabled_controls": disabled_controls,
                    "executed_steps": [
                        step["event_type"] for step in executed_steps
                    ],
                    "blocked_at": branch_result.get("blocked_at"),
                    "status": branch_result.get("status"),
                    "explanation": (
                        f"Branch {branch_number} remained exploitable in "
                        f"scenario {scenario['scenario']}. The report lists "
                        f"{', '.join(disabled_controls) if disabled_controls else 'no disabled controls'} "
                        "as disabled in this scenario."
                    ),
                })

            root_cause_details = [
                {
                    "event": event_type,
                    "explanation": self.EVENT_DETAILS.get(
                        event_type,
                        "Review this event for potential security risks.",
                    ),
                }
                for event_type in attack_sequence
            ]

            diagnoses.append({
                "branch": branch_number,
                "attack_sequence": attack_sequence,
                "root_cause_details": root_cause_details,
                "vulnerable_scenarios": vulnerable_scenarios,
                "scenario_details": scenario_details,
                "root_cause_details": root_cause_details,
                "explanation": (
                    "This branch remained exploitable in one or more "
                    "simulated control-failure scenarios."
                ),
            })

        recommendations = []

        for control in observed_controls:
            details = self.CONTROL_DETAILS.get(control, {})
            recommendations.append({
                "control": control,
                "priority": details.get("priority", 4),
                "recommendation": details.get(
                    "purpose",
                    "Review this control against the security policy.",
                ),
            })

        recommendations.sort(
            key=lambda item: (item["priority"], item["control"])
        )

        return {
            "status": "GENERATED",
            "diagnosis_count": len(diagnoses),
            "diagnoses": diagnoses,
            "recommendations": recommendations,
            "message": (
                "Findings describe simulated control-failure scenarios; "
                "they do not establish real-world causation."
            ),
        }
