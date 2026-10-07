from app.database import get_connection

connection = get_connection()
cursor = connection.cursor()

cursor.execute("""
    SELECT *
    FROM capabilities
""")

rows = cursor.fetchall()

for row in rows:
    print(row)

connection.close()