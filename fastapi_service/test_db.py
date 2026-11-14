from database import get_db_connection

connection = get_db_connection()

if connection:
    print("CyberShield Database is Ready!")
    connection.close()
else:
    print("Database Connection Failed!")