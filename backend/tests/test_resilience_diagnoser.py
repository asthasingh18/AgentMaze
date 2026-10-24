
from app.security.resilience_diagnoser import ResilienceDiagnoser


def test_diagnoses_vulnerable_branches():
    report = {
        "status": "GENERATED",
        "results": [
            {
                "scenario": 1,
                "disabled_controls": [],
                "branch_results": [],
            },
            {
                "scenario": 2,
                "disabled_controls": [
                    "GOAL_VALIDATION",
                    "MEMORY_PROVENANCE_CHECK",
                    "CAPABILITY_VERIFICATION",
                    "MCP_PROVENANCE_CHECK",
                ],
                "branch_results": [
                    {
                        "branch": 1,
                        "status": "FAIL",
                        "blocked_at": None,
                        "executed_steps": [
                            {"event_type": "GOAL_HIJACKING"},
                            {"event_type": "SESSION_CONTEXT_CONTAMINATION"},
                            {"event_type": "INTER_AGENT_TRUST_ESCALATION"},
                        ],
                    },
                    {
                        "branch": 2,
                        "status": "FAIL",
                        "blocked_at": None,
                        "executed_steps": [
                            {"event_type": "GOAL_HIJACKING"},
                            {"event_type": "MCP_TOOL_ABUSE"},
                        ],
                    },
                ],
            },
        ],
        "vulnerable_branches": [
            {
                "branch": 1,
                "attack_sequence": [
                    "GOAL_HIJACKING",
                    "SESSION_CONTEXT_CONTAMINATION",
                    "INTER_AGENT_TRUST_ESCALATION",
                ],
                "vulnerable_scenarios": [2],
            },
            {
                "branch": 2,
                "attack_sequence": [
                    "GOAL_HIJACKING",
                    "MCP_TOOL_ABUSE",
                ],
                "vulnerable_scenarios": [2],
            },
        ],
    }

    diagnosis = ResilienceDiagnoser().diagnose(report)

    assert diagnosis["status"] == "GENERATED"
    assert diagnosis["diagnosis_count"] == 2
    assert len(diagnosis["recommendations"]) == 4
    assert diagnosis["diagnoses"][0]["branch"] == 1
    assert diagnosis["diagnoses"][1]["branch"] == 2

    assert "root_cause_details" in diagnosis["diagnoses"][0]

    root_causes = diagnosis["diagnoses"][0]["root_cause_details"]

    assert len(root_causes) > 0
    assert root_causes[0]["event"] == "GOAL_HIJACKING"
    assert root_causes[0]["explanation"]

    print("PASS: Both vulnerable branches were diagnosed.")
    print("PASS: Disabled controls produced recommendations.")
    print("Diagnoses:", diagnosis["diagnosis_count"])
    print("Recommendations:", len(diagnosis["recommendations"]))


def test_handles_no_attack_paths():
    diagnosis = ResilienceDiagnoser().diagnose({
        "status": "NO_PATHS"
    })

    assert diagnosis["status"] == "NOT_TESTED"
    assert diagnosis["diagnoses"] == []
    assert diagnosis["recommendations"] == []

    print("PASS: Empty attack-path reports are handled.")


if __name__ == "__main__":
    test_diagnoses_vulnerable_branches()
    test_handles_no_attack_paths()
    print("\nALL RESILIENCE DIAGNOSER TESTS PASSED.")
