
from app.security.resilience_analyzer import ResilienceAnalyzer


def main():
    analyzer = ResilienceAnalyzer()

    # Case 1: No attack paths.
    empty_report = analyzer.analyze([])

    assert empty_report["status"] == "NO_PATHS"
    assert empty_report["scenario_count"] == 0
    assert empty_report["results"] == []
    print("PASS: Empty attack-path input is handled correctly.")

    # Case 2: Explicitly supplied empty failure scenario.
    # An empty set means no controls are disabled.
    report = analyzer.analyze(
        [],
        failure_scenarios=[set()]
    )

    assert report["status"] == "NO_PATHS"
    print("PASS: Empty input remains safe with custom scenarios.")

    print("\nRESILIENCE EDGE-CASE TESTS PASSED")


if __name__ == "__main__":
    main()
