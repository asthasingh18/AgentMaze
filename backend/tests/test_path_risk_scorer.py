
from types import SimpleNamespace

from app.security.path_risk_scorer import PathRiskScorer


def make_event(severity="LOW", event_type="TEST_EVENT"):
    """Create a lightweight event for testing the scorer."""
    return SimpleNamespace(
        severity=severity,
        event_type=event_type,
    )


def make_path(*severities):
    """Create an attack path from a sequence of severities."""
    return [
        make_event(severity, f"EVENT_{index}")
        for index, severity in enumerate(severities, start=1)
    ]


def test_empty_path_has_zero_score():
    scorer = PathRiskScorer()

    assert scorer.calculate_score([]) == 0


def test_severity_weights_are_applied():
    scorer = PathRiskScorer()

    path = make_path("LOW", "MEDIUM", "HIGH", "CRITICAL")

    assert scorer.calculate_score(path) == 12


def test_unknown_severity_defaults_to_one():
    scorer = PathRiskScorer()

    path = [make_event("UNKNOWN")]

    assert scorer.calculate_score(path) == 1


def test_three_events_add_chain_bonus():
    scorer = PathRiskScorer()

    path = make_path("LOW", "LOW", "LOW")

    # Three event points + 2 chain-complexity points.
    assert scorer.calculate_score(path) == 5


def test_five_events_add_both_chain_bonuses():
    scorer = PathRiskScorer()

    path = make_path("LOW", "LOW", "LOW", "LOW", "LOW")

    # Five event points + 2 + 3 chain-complexity points.
    assert scorer.calculate_score(path) == 10


def test_risk_level_thresholds():
    scorer = PathRiskScorer()

    assert scorer.get_risk_level(0) == "LOW"
    assert scorer.get_risk_level(3) == "LOW"
    assert scorer.get_risk_level(4) == "MEDIUM"
    assert scorer.get_risk_level(7) == "MEDIUM"
    assert scorer.get_risk_level(8) == "HIGH"
    assert scorer.get_risk_level(11) == "HIGH"
    assert scorer.get_risk_level(12) == "CRITICAL"


def test_score_path_returns_expected_details():
    scorer = PathRiskScorer()

    path = make_path("HIGH", "MEDIUM")

    result = scorer.score_path(path)

    assert result == {
        "score": 5,
        "risk_level": "MEDIUM",
        "length": 2,
    }


def test_rank_paths_sorts_by_score_descending():
    scorer = PathRiskScorer()

    paths = [
        [make_event("LOW", "LOW_EVENT")],
        [make_event("CRITICAL", "CRITICAL_EVENT")],
        [make_event("MEDIUM", "MEDIUM_EVENT")],
    ]

    results = scorer.rank_paths(paths)

    assert [item["score"] for item in results] == [4, 2, 1]
    assert [item["path_number"] for item in results] == [2, 3, 1]


def test_rank_paths_preserves_event_types():
    scorer = PathRiskScorer()

    paths = [[
        make_event("HIGH", "GOAL_HIJACKING"),
        make_event("HIGH", "INTER_AGENT_TRUST_ESCALATION"),
    ]]

    results = scorer.rank_paths(paths)

    assert results[0]["path"] == [
        "GOAL_HIJACKING",
        "INTER_AGENT_TRUST_ESCALATION",
    ]
    assert results[0]["length"] == 2
    assert results[0]["risk_level"] == "MEDIUM"


def test_rank_paths_handles_empty_input():
    scorer = PathRiskScorer()

    assert scorer.rank_paths([]) == []
