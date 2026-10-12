
from app.database import create_tables, get_connection

create_tables()

connection = get_connection()
cursor = connection.cursor()

cursor.execute("""
    SELECT name
    FROM sqlite_master
    WHERE type = 'table'
      AND name IN ('attack_paths', 'attack_path_events')
    ORDER BY name
""")

tables = cursor.fetchall()

print("New tables:", tables)

connection.close()
