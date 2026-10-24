
from app.security.attack_event import AttackEvent
from app.security.attack_explorer import AttackExplorer


class TestAttackManager:
    """Provides in-memory events without using the database."""

    def __init__(self, events):
        self.events = events


def test_attack_branches_remain_separate():
    # Create the root event.
    root = AttackEvent(
        event_type="GOAL_HIJACKING",
        agent_id="A001",
        description="Untrusted input redirects the agent goal",
        severity="HIGH"
    )
    root.event_id = "TEST-001"

    # Branch 1: context contamination.
    context = AttackEvent(
        event_type="SESSION_CONTEXT_CONTAMINATION",
        agent_id="A001",
        description="Untrusted input contaminates session context",
        severity="HIGH",
        parent_event_ids=["TEST-001"],
        relation="ENABLES"
    )
    context.event_id = "TEST-002"

    # Branch 2: tool abuse.
    tool_abuse = AttackEvent(
        event_type="MCP_TOOL_ABUSE",
        agent_id="A001",
        description="Poisoned tool instruction influences behavior",
        severity="HIGH",
        parent_event_ids=["TEST-001"],
        relation="ENABLES"
    )
    tool_abuse.event_id = "TEST-003"

    # Context contamination leads to trust escalation.
    trust = AttackEvent(
        event_type="INTER_AGENT_TRUST_ESCALATION",
        agent_id="A001",
        description="Unauthorized capability delegation attempted",
        severity="HIGH",
        parent_event_ids=["TEST-002"],
        relation="ENABLES"
    )
    trust.event_id = "TEST-004"

    manager = TestAttackManager([
        root,
        context,
        tool_abuse,
        trust
    ])

    explorer = AttackExplorer(manager)
    paths = explorer.discover_paths()

    sequences = [
        [event.event_type for event in path]
        for path in paths
    ]

    expected_paths = [
        [
            "GOAL_HIJACKING",
            "SESSION_CONTEXT_CONTAMINATION",
            "INTER_AGENT_TRUST_ESCALATION"
        ],
        [
            "GOAL_HIJACKING",
            "MCP_TOOL_ABUSE"
        ]
    ]

    assert len(sequences) == 2, (
        f"Expected 2 separate paths, got {len(sequences)}: {sequences}"
    )

    assert all(path in sequences for path in expected_paths), (
        f"Expected paths not found. Actual paths: {sequences}"
    )

    assert not any(
        "MCP_TOOL_ABUSE" in path
        and "INTER_AGENT_TRUST_ESCALATION" in path
        for path in sequences
    ), "Separate branches were incorrectly combined."

    print("PASS: Two separate attack paths discovered.")
    print("PASS: Context contamination leads to trust escalation.")
    print("PASS: MCP tool abuse remains a separate branch.")
    print("ATTACK BRANCH DISCOVERY TEST PASSED")


if __name__ == "__main__":
    test_attack_branches_remain_separate()
