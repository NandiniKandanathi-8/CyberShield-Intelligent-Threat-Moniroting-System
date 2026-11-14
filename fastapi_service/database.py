import mysql.connector
from mysql.connector import Error

def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="nandini",
            database="cybershield"
        )

        if connection.is_connected():
            print("MySQL Database Connected Successfully!")

        return connection

    except Error as e:
        print("Database Connection Error:", e)
        return None