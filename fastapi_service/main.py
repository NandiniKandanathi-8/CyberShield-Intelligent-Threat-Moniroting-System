
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from database import get_db_connection
import bcrypt

app = FastAPI(title="CyberShield API")


@app.get("/")
def home():
    return {"message": "Welcome to CyberShield API"}


# Request Models
class SecurityLog(BaseModel):
    ip_address: str
    event_type: str
    username: str = "Unknown"
    status: str = "Failed"


class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


# 1. User Registration with Password Hashing
@app.post("/auth/register")
def register_user(user: RegisterRequest):

    if not user.name.strip() or not user.email.strip():
        raise HTTPException(
            status_code=400,
            detail="Name and email are required"
        )

    if len(user.password.encode("utf-8")) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least 8 bytes"
        )

    if len(user.password.encode("utf-8")) > 72:
        raise HTTPException(
            status_code=400,
            detail="Password must not exceed 72 bytes"
        )

    connection = get_db_connection()

    if connection is None:
        raise HTTPException(
            status_code=500,
            detail="Database connection failed"
        )

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            "SELECT id FROM users WHERE email = %s",
            (user.email.strip(),)
        )

        if cursor.fetchone():
            raise HTTPException(
                status_code=409,
                detail="Email already registered"
            )

        hashed_password = bcrypt.hashpw(
            user.password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        query = """
        INSERT INTO users (name, email, password, role)
        VALUES (%s, %s, %s, %s)
        """

        cursor.execute(
            query,
            (
                user.name.strip(),
                user.email.strip(),
                hashed_password,
                "user"
            )
        )

        connection.commit()

        return {
            "message": "User registered successfully",
            "user_id": cursor.lastrowid,
            "email": user.email.strip()
        }

    except HTTPException:
        raise

    except Exception as e:
        connection.rollback()
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if cursor:
            cursor.close()
        connection.close()


# 2. User Login with Password Verification
@app.post("/auth/login")
def login_user(user: LoginRequest):

    connection = get_db_connection()

    if connection is None:
        raise HTTPException(
            status_code=500,
            detail="Database connection failed"
        )

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, name, email, password, role
            FROM users
            WHERE email = %s
            """,
            (user.email.strip(),)
        )

        db_user = cursor.fetchone()

        if not db_user:
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password"
            )

        stored_hash = db_user["password"].encode("utf-8")

        if not bcrypt.checkpw(
            user.password.encode("utf-8"),
            stored_hash
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid email or password"
            )

        return {
            "message": "Login successful",
            "user": {
                "id": db_user["id"],
                "name": db_user["name"],
                "email": db_user["email"],
                "role": db_user["role"]
            }
        }

    except HTTPException:
        raise

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if cursor:
            cursor.close()
        connection.close()


# 3. Save Security Logs
@app.post("/logs")
def create_log(log: SecurityLog):
    connection = get_db_connection()

    if connection is None:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = None

    try:
        cursor = connection.cursor()

        query = """
        INSERT INTO security_logs
        (ip_address, event_type, username, status)
        VALUES (%s, %s, %s, %s)
        """

        values = (
            log.ip_address,
            log.event_type,
            log.username,
            log.status
        )

        cursor.execute(query, values)
        connection.commit()

        return {
            "message": "Security log saved successfully",
            "log_id": cursor.lastrowid
        }

    except Exception as e:
        connection.rollback()
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if cursor:
            cursor.close()
        connection.close()


# 4. Get All Security Logs
@app.get("/security-logs")
def get_security_logs():
    connection = get_db_connection()

    if connection is None:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        query = """
        SELECT id, ip_address, event_type, username, status, created_at
        FROM security_logs
        ORDER BY id DESC
        """

        cursor.execute(query)
        logs = cursor.fetchall()

        return {
            "total_logs": len(logs),
            "logs": logs
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if cursor:
            cursor.close()
        connection.close()


# 5. Detect Threats and Create Automatic Alerts
@app.get("/detect-threats")
def detect_threats():
    connection = get_db_connection()

    if connection is None:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        query = """
        SELECT
            ip_address,
            COUNT(*) AS failed_attempts,
            MAX(id) AS latest_log_id
        FROM security_logs
        WHERE status = 'Failed'
        GROUP BY ip_address
        HAVING COUNT(*) >= 3
        """

        cursor.execute(query)
        threats = cursor.fetchall()

        alerts_created = 0

        for threat in threats:
            ip = threat["ip_address"]
            attempts = threat["failed_attempts"]
            log_id = threat["latest_log_id"]

            message = (
                f"Suspicious IP {ip}: "
                f"{attempts} failed login attempts"
            )

            check_query = """
            SELECT id
            FROM alerts
            WHERE alert_type = 'Repeated Failed Login'
            AND message LIKE %s
            LIMIT 1
            """

            cursor.execute(check_query, (f"%{ip}%",))
            existing_alert = cursor.fetchone()

            if not existing_alert:
                insert_query = """
                INSERT INTO alerts
                (log_id, alert_type, severity, message, status)
                VALUES (%s, %s, %s, %s, %s)
                """

                cursor.execute(
                    insert_query,
                    (
                        log_id,
                        "Repeated Failed Login",
                        "High",
                        message,
                        "New"
                    )
                )

                alerts_created += 1

        connection.commit()

        return {
            "message": "Threat detection completed",
            "total_threats": len(threats),
            "alerts_created": alerts_created,
            "threats": threats
        }

    except Exception as e:
        connection.rollback()
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if cursor:
            cursor.close()
        connection.close()


# 6. Dashboard Statistics
@app.get("/stats")
def get_stats():
    connection = get_db_connection()

    if connection is None:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT COUNT(*) AS total_logs
            FROM security_logs
        """)
        total_logs = cursor.fetchone()["total_logs"]

        cursor.execute("""
            SELECT COUNT(*) AS failed_attempts
            FROM security_logs
            WHERE status = 'Failed'
        """)
        failed_attempts = cursor.fetchone()["failed_attempts"]

        cursor.execute("""
            SELECT COUNT(*) AS active_alerts
            FROM alerts
            WHERE status = 'New'
        """)
        active_alerts = cursor.fetchone()["active_alerts"]

        cursor.execute("""
            SELECT COUNT(*) AS total_threats
            FROM (
                SELECT ip_address
                FROM security_logs
                WHERE status = 'Failed'
                GROUP BY ip_address
                HAVING COUNT(*) >= 3
            ) AS suspicious_ips
        """)
        total_threats = cursor.fetchone()["total_threats"]

        return {
            "total_logs": total_logs,
            "failed_attempts": failed_attempts,
            "active_alerts": active_alerts,
            "total_threats": total_threats
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if cursor:
            cursor.close()
        connection.close()


# 7. Get All Security Alerts
@app.get("/alerts")
def get_alerts():
    connection = get_db_connection()

    if connection is None:
        raise HTTPException(status_code=500, detail="Database connection failed")

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        query = """
        SELECT
            id,
            log_id,
            alert_type,
            severity,
            message,
            status,
            created_at
        FROM alerts
        ORDER BY id DESC
        """

        cursor.execute(query)
        alerts = cursor.fetchall()

        return {
            "total_alerts": len(alerts),
            "alerts": alerts
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if cursor:
            cursor.close()
        connection.close()


# 8. Update Alert Status
@app.put("/alerts/{alert_id}")
def update_alert_status(alert_id: int, status: str):

    if status not in ["New", "Resolved"]:
        raise HTTPException(
            status_code=400,
            detail="Status must be New or Resolved"
        )

    connection = get_db_connection()

    if connection is None:
        raise HTTPException(
            status_code=500,
            detail="Database connection failed"
        )

    cursor = None

    try:
        cursor = connection.cursor()

        cursor.execute(
            "SELECT id FROM alerts WHERE id = %s",
            (alert_id,)
        )

        if cursor.fetchone() is None:
            raise HTTPException(
                status_code=404,
                detail="Alert not found"
            )

        cursor.execute(
            "UPDATE alerts SET status = %s WHERE id = %s",
            (status, alert_id)
        )

        connection.commit()

        return {
            "message": "Alert status updated successfully",
            "alert_id": alert_id,
            "status": status
        }

    except HTTPException:
        raise

    except Exception as e:
        connection.rollback()
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if cursor:
            cursor.close()
        connection.close()
dir