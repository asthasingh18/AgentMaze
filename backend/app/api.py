
import sqlite3
from uuid import uuid4

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import (
    DATABASE_PATH,
    load_attack_events_from_database,
    get_saved_attack_paths,
)
from app.agents.agent import Agent
from app.tools.tool import Tool
from app.simulation.environment import Environment


app = FastAPI(
    title="AgentMaze API",
    description="API for the AgentMaze agent security simulation.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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

    # Register the scenario and agents in SQLite.
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

    # Run the simulation using the registered IDs.
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


@app.post("/api/resilience-analysis")
def analyze_resilience():
    # Generate unique IDs for this resilience test.
    run_id = uuid4().hex[:8]
    scenario_id = f"RES-S-{run_id}"
    agent_a_id = f"RES-A-{run_id}"
    agent_b_id = f"RES-B-{run_id}"

    # Register the scenario and agents before recording attack events.
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
                "Resilience analysis test",
                "Controlled agent delegation resilience test",
                __import__("datetime").datetime.now().isoformat(),
                "running",
            ),
        )

        cursor.execute(
            """
            INSERT INTO agents (agent_id, scenario_id, name)
            VALUES (?, ?, ?)
            """,
            (agent_a_id, scenario_id, "Resilience-Agent-A"),
        )

        cursor.execute(
            """
            INSERT INTO agents (agent_id, scenario_id, name)
            VALUES (?, ?, ?)
            """,
            (agent_b_id, scenario_id, "Resilience-Agent-B"),
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    # Create the controlled simulation environment.
    environment = Environment()

    agent_a = Agent(
        agent_id=agent_a_id,
        name="Resilience-Agent-A",
        permissions=["customer_search"],
    )

    agent_b = Agent(
        agent_id=agent_b_id,
        name="Resilience-Agent-B",
        permissions=["customer_search"],
    )

    environment.add_agent(agent_a)
    environment.add_agent(agent_b)

    # Scenario 1: Authorized delegation should succeed.
    authorized = environment.delegate_task(
        from_agent_id=agent_a_id,
        to_agent_id=agent_b_id,
        task="Search customer information",
        required_capability="customer_search",
    )

    # Scenario 2: Unauthorized delegation should be blocked.
    unauthorized = environment.delegate_task(
        from_agent_id=agent_a_id,
        to_agent_id=agent_b_id,
        task="Access database administration",
        required_capability="database_admin",
    )

    outcomes = [
        {
            "scenario": "authorized_delegation",
            "category": (
                "success"
                if authorized["success"]
                else "operational_failure"
            ),
            "success": authorized["success"],
            "message": authorized.get(
                "message", "Delegation completed"
            ),
        },
        {
            "scenario": "unauthorized_delegation",
            "category": (
                "security_block"
                if not unauthorized["success"]
                else "unexpected_success"
            ),
            "success": unauthorized["success"],
            "message": unauthorized.get(
                "message", "Delegation completed"
            ),
        },
    ]

    successful = sum(
        1 for item in outcomes if item["category"] == "success"
    )
    blocked = sum(
        1 for item in outcomes if item["category"] == "security_block"
    )
    failures = sum(
        1
        for item in outcomes
        if item["category"] == "operational_failure"
    )
    unexpected = sum(
        1
        for item in outcomes
        if item["category"] == "unexpected_success"
    )

    total = len(outcomes)
    safe_outcomes = successful + blocked

    return {
        "status": "completed",
        "run_id": run_id,
        "metrics": {
            "total_operations": total,
            "successful_operations": successful,
            "security_blocks": blocked,
            "operational_failures": failures,
            "unexpected_successes": unexpected,
            "safe_outcome_rate_percent": (
                round(safe_outcomes / total * 100, 2)
                if total
                else 0
            ),
        },
        "outcomes": outcomes,
        "events": environment.get_events(),
        "attack_events": environment.get_attack_events(),
    }
