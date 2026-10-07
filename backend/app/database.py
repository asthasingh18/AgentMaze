import sqlite3

DATABASE_PATH = "data/agentmaze.db"


def get_connection():

    connection = sqlite3.connect(DATABASE_PATH)
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def create_tables():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scenarios (
            scenario_id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            created_at TEXT,
            status TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            scenario_id TEXT,
            name TEXT,
            FOREIGN KEY (scenario_id)
                 REFERENCES scenarios(scenario_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS capabilities (
            capability_id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT
        )
    """)

    connection.commit()

    connection.close()