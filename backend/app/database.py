
import sqlite3


DATABASE_PATH = "data/agentmaze.db"


def get_connection():

    connection = sqlite3.connect(DATABASE_PATH)

    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def create_tables():

    connection = get_connection()

    cursor = connection.cursor()

    # --------------------------------------------------
    # Scenarios
    # --------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scenarios (
            scenario_id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            created_at TEXT,
            status TEXT
        )
    """)

    # --------------------------------------------------
    # Agents
    # --------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            scenario_id TEXT,
            name TEXT,

            FOREIGN KEY (scenario_id)
                REFERENCES scenarios(scenario_id)
        )
    """)

    # --------------------------------------------------
    # Capabilities
    # --------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS capabilities (
            capability_id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT
        )
    """)

    # --------------------------------------------------
    # Agent Capabilities
    # --------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS agent_capabilities (
            agent_id TEXT,
            capability_id TEXT,

            PRIMARY KEY (agent_id, capability_id),

            FOREIGN KEY (agent_id)
                REFERENCES agents(agent_id),

            FOREIGN KEY (capability_id)
                REFERENCES capabilities(capability_id)
        )
    """)

    # --------------------------------------------------
    # Tools
    # --------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tools (
            tool_id TEXT PRIMARY KEY,
            scenario_id TEXT,
            name TEXT,
            required_capability_id TEXT,

            FOREIGN KEY (scenario_id)
                REFERENCES scenarios(scenario_id),

            FOREIGN KEY (required_capability_id)
                REFERENCES capabilities(capability_id)
        )
    """)

    # --------------------------------------------------
    # Agent Tools
    # --------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS agent_tools (
            agent_id TEXT,
            tool_id TEXT,

            PRIMARY KEY (agent_id, tool_id),

            FOREIGN KEY (agent_id)
                REFERENCES agents(agent_id),

            FOREIGN KEY (tool_id)
                REFERENCES tools(tool_id)
        )
    """)

    # --------------------------------------------------
    # Attack Events
    # --------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_events (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT,
            event_type TEXT,
            agent_id TEXT,
            description TEXT,
            severity TEXT,
            source TEXT,
            target TEXT,

            FOREIGN KEY (agent_id)
                REFERENCES agents(agent_id)
        )
    """)

    # Save changes
    connection.commit()

    # Close database connection
    connection.close()


# --------------------------------------------------
# Get Agent Capabilities
# --------------------------------------------------

def get_agent_capabilities(agent_id):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT capabilities.name

        FROM agent_capabilities

        JOIN capabilities
            ON agent_capabilities.capability_id =
               capabilities.capability_id

        WHERE agent_capabilities.agent_id = ?
    """, (agent_id,))

    rows = cursor.fetchall()

    connection.close()

    return [row[0] for row in rows]


# --------------------------------------------------
# Check Agent Tool Assignment
# --------------------------------------------------

def agent_has_tool(agent_id, tool_id):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT 1

        FROM agent_tools

        WHERE agent_id = ?
        AND tool_id = ?
    """, (agent_id, tool_id))

    result = cursor.fetchone()

    connection.close()

    return result is not None

# --------------------------------------------------
# Save Attack Event
# --------------------------------------------------

def save_attack_event(event):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO attack_events (
            event_id,
            timestamp,
            event_type,
            agent_id,
            description,
            severity,
            source,
            target
        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.event_id,
        event.timestamp,
        event.event_type,
        event.agent_id,
        event.description,
        event.severity,
        event.source,
        event.target
    ))

    connection.commit()

    connection.close()
    
