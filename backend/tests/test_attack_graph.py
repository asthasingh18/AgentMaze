
from types import SimpleNamespace

from app.security.attack_graph import AttackGraph


def make_event(
    event_id,
    severity="LOW",
    parent_event_ids=None,
    relation="RELATED_TO",
    event_type="TEST_EVENT",
    agent_id="AGENT-1",
):
    return SimpleNamespace(
        event_id=event_id,
        event_type=event_type,
        agent_id=agent_id,
        severity=severity,
        parent_event_ids=parent_event_ids or [],
        relation=relation,
    )


def test_empty_graph():
    graph = AttackGraph()

    assert graph.get_graph() == {"nodes": [], "edges": []}
    assert graph.calculate_risk_score() == 0
    assert graph.get_risk_level() == "LOW"
    assert graph.find_root_causes() == []
    assert graph.find_terminal_events() == []


def test_add_node():
    graph = AttackGraph()
    event = make_event("E1", severity="HIGH")

    graph.add_node(event)

    assert graph.nodes == [
        {
            "id": "E1",
            "type": "TEST_EVENT",
            "agent": "AGENT-1",
            "severity": "HIGH",
        }
    ]


def test_build_graph_with_parent_child_events():
    graph = AttackGraph()

    root = make_event("E1", severity="HIGH")
    child = make_event(
        "E2",
        severity="MEDIUM",
        parent_event_ids=["E1"],
        relation="CAUSED_BY",
    )

    graph.build_from_events([root, child])

    result = graph.get_graph()

    assert len(result["nodes"]) == 2
    assert result["edges"] == [
        {
            "source": "E1",
            "target": "E2",
            "relation": "CAUSED_BY",
            "severity": "MEDIUM",
        }
    ]


def test_missing_parent_does_not_create_edge():
    graph = AttackGraph()

    event = make_event(
        "E1",
        parent_event_ids=["UNKNOWN-EVENT"],
    )

    graph.build_from_events([event])

    assert len(graph.nodes) == 1
    assert graph.edges == []


def test_risk_score_uses_severity_weights():
    graph = AttackGraph()
    graph.add_node(make_event("E1", "LOW"))
    graph.add_node(make_event("E2", "MEDIUM"))
    graph.add_node(make_event("E3", "HIGH"))
    graph.add_node(make_event("E4", "CRITICAL"))

    assert graph.calculate_risk_score() == 10


def test_unknown_severity_uses_default_weight():
    graph = AttackGraph()
    graph.add_node(make_event("E1", severity="UNKNOWN"))

    assert graph.calculate_risk_score() == 1


def test_attack_chain_adds_risk_bonus():
    graph = AttackGraph()

    graph.add_node(make_event("E1", "LOW"))
    graph.add_node(make_event("E2", "LOW"))
    graph.add_node(make_event("E3", "LOW"))

    graph.add_edge(
        make_event("E1"),
        make_event("E2"),
    )
    graph.add_edge(
        make_event("E2"),
        make_event("E3"),
    )

    assert graph.calculate_risk_score() == 5


def test_four_edges_add_both_risk_bonuses():
    graph = AttackGraph()

    for index in range(5):
        graph.add_node(make_event(f"E{index}", "LOW"))

    for index in range(4):
        graph.add_edge(
            make_event(f"E{index}"),
            make_event(f"E{index + 1}"),
        )

    assert graph.calculate_risk_score() == 10
    assert graph.get_risk_level() == "HIGH"


def test_risk_level_thresholds():
    cases = [
        (3, "LOW"),
        (4, "MEDIUM"),
        (8, "HIGH"),
        (12, "CRITICAL"),
    ]

    for score, expected_level in cases:
        graph = AttackGraph()

        for index in range(score):
            graph.add_node(make_event(f"E{index}", "LOW"))

        assert graph.get_risk_level() == expected_level


def test_root_causes_and_terminal_events():
    graph = AttackGraph()

    events = [
        make_event("E1"),
        make_event("E2", parent_event_ids=["E1"]),
        make_event("E3", parent_event_ids=["E2"]),
    ]

    graph.build_from_events(events)

    assert [node["id"] for node in graph.find_root_causes()] == ["E1"]
    assert [node["id"] for node in graph.find_terminal_events()] == ["E3"]


def test_disconnected_events_are_roots_and_terminals():
    graph = AttackGraph()

    graph.build_from_events([
        make_event("E1"),
        make_event("E2"),
    ])

    assert [node["id"] for node in graph.find_root_causes()] == [
        "E1",
        "E2",
    ]
    assert [node["id"] for node in graph.find_terminal_events()] == [
        "E1",
        "E2",
    ]
