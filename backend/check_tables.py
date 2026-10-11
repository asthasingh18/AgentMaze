
from app.database import get_connection, create_tables

create_tables()

connection = get_connection()
cursor = connection.cursor()

cursor.execute("""
    SELECT name
    FROM sqlite_master
    WHERE type = 'table'
""")

for row in cursor.fetchall():
    print(row[0])

connection.close()