
import sqlite3
from uuid import uuid4
from app.database import DATABASE_PATH
from fastapi import FastAPI
from app.database import load_attack_events_from_database
from app.database import get_saved_attack_paths
from app.agents.agent import Agent
from app.tools.tool import Tool
from app.simulation.environment import Environment

app = FastAPI(
    title="AgentMaze API",
    description="API for the AgentMaze agent security simulation.",
    version="1.0.0",
)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "project": "AgentMaze",
    }

@app.get("/api/attack-events")
def get_attack_events():
    events = load_attack_events_from_database()

    return {
        "total": len(events),
        "events": [event.to_dict() for event in events],
    }

@app.get("/api/attack-paths")
def get_attack_paths():
    paths = get_saved_attack_paths()

    return {
        "total": len(paths),
        "attack_paths": paths,
    }


@app.post("/api/simulate")
def run_simulation():
    # Generate unique IDs so repeated requests do not conflict.
    run_id = uuid4().hex[:8]
    scenario_id = f"API-S-{run_id}"
    agent_a_id = f"API-A-{run_id}"
    agent_b_id = f"API-B-{run_id}"

    # Register the scenario and agents before creating attack events.
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)

    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO scenarios (
                scenario_id, name, description, created_at, status
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                scenario_id,
                "Agent delegation security test",
                "API-generated delegation security simulation",
                __import__("datetime").datetime.now().isoformat(),
                "running",
            ),
        )

        cursor.execute(
            """
            INSERT INTO agents (agent_id, scenario_id, name)
            VALUES (?, ?, ?)
            """,
            (agent_a_id, scenario_id, "API-Agent-A"),
        )

        cursor.execute(
            """
            INSERT INTO agents (agent_id, scenario_id, name)
            VALUES (?, ?, ?)
            """,
            (agent_b_id, scenario_id, "API-Agent-B"),
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    # Run the simulation using the same IDs registered in the database.
    environment = Environment()

    agent_a = Agent(
        agent_id=agent_a_id,
        name="API-Agent-A",
        permissions=["customer_search"],
    )

    agent_b = Agent(
        agent_id=agent_b_id,
        name="API-Agent-B",
        permissions=["customer_search"],
    )

    environment.add_agent(agent_a)
    environment.add_agent(agent_b)

    environment.add_tool(
        Tool(
            tool_id=f"API-T-{run_id}",
            name="Customer Search",
            required_permission="customer_search",
        )
    )

    successful_delegation = environment.delegate_task(
        from_agent_id=agent_a_id,
        to_agent_id=agent_b_id,
        task="Search customer information",
        required_capability="customer_search",
    )

    blocked_delegation = environment.delegate_task(
        from_agent_id=agent_a_id,
        to_agent_id=agent_b_id,
        task="Access database administration",
        required_capability="database_admin",
    )

    return {
        "status": "completed",
        "scenario": "Agent delegation security test",
        "scenario_id": scenario_id,
        "results": {
            "authorized_delegation": successful_delegation,
            "unauthorized_delegation": blocked_delegation,
        },
        "attack_events": environment.get_attack_events(),
    }
