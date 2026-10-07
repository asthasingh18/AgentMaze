from app.database import create_tables, get_connection

create_tables()

connection = get_connection()
cursor = connection.cursor()

cursor.execute("""
    INSERT INTO capabilities (
        capability_id,
        name,
        description
    )
    VALUES (?, ?, ?)
""", (
    "CAP002",
    "database_admin",
    "Perform database administration."
))

connection.commit()

print("Capability inserted successfully")

connection.close()