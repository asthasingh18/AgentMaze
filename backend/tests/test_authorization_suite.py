
import os
import tempfile

import app.database as database
from app.agents.agent import Agent
from app.tools.tool import Tool
from app.simulation.environment import Environment


def setup_test_data():
    """Create test records in the isolated test database."""
    database.create_tables()

    connection = database.get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("""
            INSERT INTO scenarios
            (scenario_id, name, description, created_at, status)
            VALUES ('TEST-SC-01', 'Authorization Test',
                    'Automated authorization tests', '', 'ACTIVE')
        """)

        cursor.executemany("""
            INSERT INTO agents (agent_id, scenario_id, name)
            VALUES (?, 'TEST-SC-01', ?)
        """, [
            ("TEST-A01", "Authorized Agent"),
            ("TEST-A02", "Unassigned Agent"),
            ("TEST-A03", "Insufficient Agent"),
        ])

        cursor.executemany("""
            INSERT INTO capabilities
            (capability_id, name, description)
            VALUES (?, ?, ?)
        """, [
            ("TEST-C01", "customer_search", "Search customer records"),
            ("TEST-C02", "database_admin", "Administrative database access"),
        ])

        cursor.execute("""
            INSERT INTO tools
            (tool_id, scenario_id, name, required_capability_id)
            VALUES ('TEST-T01', 'TEST-SC-01', 'Customer Search', 'TEST-C01')
        """)

        # A01 and A02 have the required capability.
        cursor.executemany("""
            INSERT INTO agent_capabilities (agent_id, capability_id)
            VALUES (?, 'TEST-C01')
        """, [
            ("TEST-A01",),
            ("TEST-A02",),
        ])

        # A01 and A03 are assigned the tool.
        cursor.executemany("""
            INSERT INTO agent_tools (agent_id, tool_id)
            VALUES (?, 'TEST-T01')
        """, [
            ("TEST-A01",),
            ("TEST-A03",),
        ])

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
    original_database_path = database.DATABASE_PATH

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            database.DATABASE_PATH = os.path.join(
                temp_dir, "agentmaze_test.db"
            )

            setup_test_data()

            cases = [
                (
                    "Assigned agent with required capability is allowed",
                    "TEST-A01", "TEST-T01", True,
                ),
                (
                    "Unassigned agent is denied despite having capability",
                    "TEST-A02", "TEST-T01", False,
                ),
                (
                    "Assigned agent without required capability is denied",
                    "TEST-A03", "TEST-T01", False,
                ),
                (
                    "Unknown tool is denied",
                    "TEST-A01", "TEST-T99", False,
                ),
            ]

            results = [
                run_case(name, agent_id, tool_id, expected)
                for name, agent_id, tool_id, expected in cases
            ]

            passed_count = sum(results)
            print(
                f"\nAuthorization tests passed: "
                f"{passed_count}/{len(results)}"
            )

            if not all(results):
                raise SystemExit(1)

            print("AUTHORIZATION SUITE PASSED")

    finally:
        database.DATABASE_PATH = original_database_path


if __name__ == "__main__":
    main()
