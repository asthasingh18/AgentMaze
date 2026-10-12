
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
    
    # --------------------------------------------------
    # Event Dependencies
    # --------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS event_dependencies (
            parent_event_id TEXT,
            child_event_id TEXT,
            relation TEXT,

            PRIMARY KEY (parent_event_id, child_event_id),

            FOREIGN KEY (parent_event_id)
                REFERENCES attack_events(event_id),

            FOREIGN KEY (child_event_id)
                REFERENCES attack_events(event_id)
        )
    """)
    
    # --------------------------------------------------
    # Attack Paths
    # --------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_paths (
            path_id TEXT PRIMARY KEY,
            created_at TEXT,
            risk_level TEXT,
            description TEXT
        )
    """)

    # --------------------------------------------------
    # Attack Path Events
    # --------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_path_events (
            path_id TEXT,
            event_id TEXT,
            event_order INTEGER,

            PRIMARY KEY (path_id, event_order),

            FOREIGN KEY (path_id)
                REFERENCES attack_paths(path_id),

            FOREIGN KEY (event_id)
                REFERENCES attack_events(event_id)
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
# --------------------------------------------------
# Save Event Dependency
# --------------------------------------------------

def save_event_dependency(parent_event_id, child_event_id, relation):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT OR IGNORE INTO event_dependencies (
            parent_event_id,
            child_event_id,
            relation
        )
        VALUES (?, ?, ?)
    """, (
        parent_event_id,
        child_event_id,
        relation
    ))

    connection.commit()
    connection.close()
    
# --------------------------------------------------
# Get Event Dependencies
# --------------------------------------------------

def get_event_dependencies():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            parent_event_id,
            child_event_id,
            relation
        FROM event_dependencies
        ORDER BY parent_event_id, child_event_id
    """)

    rows = cursor.fetchall()
    connection.close()

    return [
        {
            "parent_event_id": row[0],
            "child_event_id": row[1],
            "relation": row[2]
        }
        for row in rows
    ]


# --------------------------------------------------
# Load Attack Events and Dependencies from Database
# --------------------------------------------------

def load_attack_events_from_database():

    from app.security.attack_event import AttackEvent

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            event_id,
            timestamp,
            event_type,
            agent_id,
            description,
            severity,
            source,
            target
        FROM attack_events
        ORDER BY timestamp, event_id
    """)

    rows = cursor.fetchall()

    events = {}

    for row in rows:
        event = AttackEvent(
            event_type=row[2],
            agent_id=row[3],
            description=row[4],
            severity=row[5],
            source=row[6],
            target=row[7]
        )

        event.event_id = row[0]
        event.timestamp = row[1]

        events[event.event_id] = event

    cursor.execute("""
        SELECT
            parent_event_id,
            child_event_id,
            relation
        FROM event_dependencies
    """)

    dependencies = cursor.fetchall()

    connection.close()

    for parent_id, child_id, relation in dependencies:
        if child_id in events and parent_id in events:
            events[child_id].parent_event_ids.append(parent_id)

    return list(events.values())


# --------------------------------------------------
# Save Discovered Attack Path
# --------------------------------------------------

def save_attack_path(path_id, events, risk_level=None, description=None):

    from datetime import datetime

    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("""
            INSERT OR REPLACE INTO attack_paths (
                path_id,
                created_at,
                risk_level,
                description
            )
            VALUES (?, ?, ?, ?)
        """, (
            path_id,
            datetime.now().isoformat(),
            risk_level,
            description
        ))

        # Remove old event links if this path is being saved again.
        cursor.execute("""
            DELETE FROM attack_path_events
            WHERE path_id = ?
        """, (path_id,))

        for order, event in enumerate(events, start=1):
            event_id = (
                event.event_id
                if hasattr(event, "event_id")
                else event["event_id"]
            )

            cursor.execute("""
                INSERT INTO attack_path_events (
                    path_id,
                    event_id,
                    event_order
                )
                VALUES (?, ?, ?)
            """, (
                path_id,
                event_id,
                order
            ))

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


# --------------------------------------------------
# Read Saved Attack Paths
# --------------------------------------------------

def get_saved_attack_paths():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            path_id,
            created_at,
            risk_level,
            description
        FROM attack_paths
        ORDER BY path_id
    """)

    paths = cursor.fetchall()

    results = []

    for path_id, created_at, risk_level, description in paths:

        cursor.execute("""
            SELECT
                attack_path_events.event_order,
                attack_events.event_id,
                attack_events.event_type
            FROM attack_path_events
            JOIN attack_events
                ON attack_path_events.event_id = attack_events.event_id
            WHERE attack_path_events.path_id = ?
            ORDER BY attack_path_events.event_order
        """, (path_id,))

        events = cursor.fetchall()

        results.append({
            "path_id": path_id,
            "created_at": created_at,
            "risk_level": risk_level,
            "description": description,
            "events": [
                {
                    "event_order": row[0],
                    "event_id": row[1],
                    "event_type": row[2]
                }
                for row in events
            ]
        })

    connection.close()

    return results


