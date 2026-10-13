
import sqlite3

from app.database import create_tables
from app.agents.agent import Agent
from app.tools.tool import Tool
from app.simulation.environment import Environment


DATABASE_PATH = "data/agentmaze.db"


def setup_test_data():
    """Create isolated test records for authorization checks."""
    create_tables()

    connection = sqlite3.connect(DATABASE_PATH)
    connection.execute("PRAGMA foreign_keys = ON")

    try:
        cursor = connection.cursor()

        # Use dedicated IDs so we don't overwrite existing project records.
        cursor.execute("""
            INSERT OR IGNORE INTO scenarios
            (scenario_id, name, description, created_at, status)
            VALUES ('TEST-SC-01', 'Authorization Test',
                    'Automated authorization tests', '', 'ACTIVE')
        """)

        cursor.execute("""
            INSERT OR IGNORE INTO agents (agent_id, scenario_id, name)
            VALUES ('TEST-A01', 'TEST-SC-01', 'Authorized Agent')
        """)

        cursor.execute("""
            INSERT OR IGNORE INTO agents (agent_id, scenario_id, name)
            VALUES ('TEST-A02', 'TEST-SC-01', 'Unassigned Agent')
        """)

        cursor.execute("""
            INSERT OR IGNORE INTO agents (agent_id, scenario_id, name)
            VALUES ('TEST-A03', 'TEST-SC-01', 'Insufficient Agent')
        """)

        cursor.execute("""
            INSERT OR IGNORE INTO capabilities
            (capability_id, name, description)
            VALUES ('TEST-C01', 'customer_search', 'Search customer records')
        """)

        cursor.execute("""
            INSERT OR IGNORE INTO capabilities
            (capability_id, name, description)
            VALUES ('TEST-C02', 'database_admin', 'Administrative database access')
        """)

        cursor.execute("""
            INSERT OR IGNORE INTO tools
            (tool_id, scenario_id, name, required_capability_id)
            VALUES ('TEST-T01', 'TEST-SC-01', 'Customer Search', 'TEST-C01')
        """)

        # Give TEST-A01 customer_search.
        cursor.execute("""
            INSERT OR IGNORE INTO agent_capabilities
            (agent_id, capability_id)
            VALUES ('TEST-A01', 'TEST-C01')
        """)

        # TEST-A02 also has customer_search, but won't be assigned the tool.
        cursor.execute("""
            INSERT OR IGNORE INTO agent_capabilities
            (agent_id, capability_id)
            VALUES ('TEST-A02', 'TEST-C01')
        """)

        # TEST-A03 is assigned the tool but lacks customer_search.
        cursor.execute("""
            INSERT OR IGNORE INTO agent_tools (agent_id, tool_id)
            VALUES ('TEST-A01', 'TEST-T01')
        """)

        cursor.execute("""
            INSERT OR IGNORE INTO agent_tools (agent_id, tool_id)
            VALUES ('TEST-A03', 'TEST-T01')
        """)

        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def run_case(name, agent_id, tool_id, expected_success):
    environment = Environment()

    agents = {
        "TEST-A01": Agent("TEST-A01", "Authorized Agent"),
        "TEST-A02": Agent("TEST-A02", "Unassigned Agent"),
        "TEST-A03": Agent("TEST-A03", "Insufficient Agent"),
    }

    for agent in agents.values():
        environment.add_agent(agent)

    environment.add_tool(
        Tool(
            tool_id="TEST-T01",
            name="Customer Search",
            required_permission="customer_search",
        )
    )

    result = environment.run_tool(agent_id, tool_id)
    passed = result["success"] is expected_success

    print(f"{'PASS' if passed else 'FAIL'}: {name}")
    print(f"  Result: {result}")

    return passed


def main():
    setup_test_data()

    cases = [
        (
            "Assigned agent with required capability is allowed",
            "TEST-A01",
            "TEST-T01",
            True,
        ),
        (
            "Unassigned agent is denied despite having capability",
            "TEST-A02",
            "TEST-T01",
            False,
        ),
        (
            "Assigned agent without required capability is denied",
            "TEST-A03",
            "TEST-T01",
            False,
        ),
        (
            "Unknown tool is denied",
            "TEST-A01",
            "TEST-T99",
            False,
        ),
    ]

    results = [
        run_case(name, agent_id, tool_id, expected)
        for name, agent_id, tool_id, expected in cases
    ]

    print(f"\nAuthorization tests passed: {sum(results)}/{len(results)}")

    if not all(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
