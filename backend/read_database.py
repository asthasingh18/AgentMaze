
from app.database import get_connection


connection = get_connection()
cursor = connection.cursor()


# --------------------------------------------------
# Agent Tool Authorization
# --------------------------------------------------

cursor.execute("""
    SELECT
        scenarios.name,
        agents.name,
        tools.name,
        capabilities.name

    FROM agent_tools

    JOIN agents
        ON agent_tools.agent_id = agents.agent_id

    JOIN tools
        ON agent_tools.tool_id = tools.tool_id

    JOIN capabilities
        ON tools.required_capability_id = capabilities.capability_id

    JOIN scenarios
        ON agents.scenario_id = scenarios.scenario_id
""")


rows = cursor.fetchall()


print("AGENT TOOL AUTHORIZATION:")

for row in rows:
    print(row)


# --------------------------------------------------
# Attack Events
# --------------------------------------------------

cursor.execute("""
    SELECT
        event_id,
        event_type,
        agent_id,
        severity,
        description

    FROM attack_events
""")


attack_events = cursor.fetchall()


print("\nATTACK EVENTS IN DATABASE:")

for event in attack_events:
    print(event)


connection.close()
