
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session
)
from functools import wraps
import requests

app = Flask(__name__)
app.secret_key = "cybershield_secret_key"

API_URL = "http://localhost:8000"


# Login Required Decorator
def login_required(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            flash("Please login first!", "error")
            return redirect(url_for("home"))

        return route_function(*args, **kwargs)

    return wrapper


# 1. Home / Login Page
@app.route("/")
def home():
    if "user" in session:
        return redirect(url_for("dashboard"))

    return render_template("login.html")


# 2. Registration Page
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "GET":
        return render_template("register.html")

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    if not name or not email or not password:
        flash("Please fill all fields.", "error")
        return redirect(url_for("register"))

    try:
        response = requests.post(
            f"{API_URL}/auth/register",
            json={
                "name": name,
                "email": email,
                "password": password
            },
            timeout=10
        )

        print("Register Status:", response.status_code)
        print("Register Response:", response.text)

        if response.status_code in (200, 201):
            flash("Registration successful! Please login.", "success")
            return redirect(url_for("home"))

        elif response.status_code == 409:
            flash("Email already registered. Please login.", "error")

        elif response.status_code == 422:
            flash("Invalid registration details. Check your input.", "error")

        else:
            flash("Registration failed. Please try again.", "error")

    except requests.RequestException as e:
        print("Registration API Error:", e)
        flash("FastAPI server is not connected.", "error")

    return redirect(url_for("register"))


# 3. Login using FastAPI
@app.route("/login", methods=["POST"])
def login():

    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    if not email or not password:
        flash("Please enter email and password.", "error")
        return redirect(url_for("home"))

    try:
        response = requests.post(
            f"{API_URL}/auth/login",
            json={
                "email": email,
                "password": password
            },
            timeout=10
        )

        print("Login Status:", response.status_code)
        print("Login Response:", response.text)

        if response.status_code == 200:
            data = response.json()
            session["user"] = data["user"]

            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))

        elif response.status_code == 401:
            flash("Invalid email or password.", "error")

        else:
            flash("Login failed. Please try again.", "error")

    except requests.RequestException as e:
        print("Login API Error:", e)
        flash("FastAPI server is not connected.", "error")

    return redirect(url_for("home"))


# 4. Dashboard
@app.route("/dashboard")
@login_required
def dashboard():

    try:
        stats_response = requests.get(
            f"{API_URL}/stats",
            timeout=5
        )
        stats_response.raise_for_status()
        stats = stats_response.json()

        threat_response = requests.get(
            f"{API_URL}/detect-threats",
            timeout=5
        )
        threat_response.raise_for_status()
        threat_data = threat_response.json()

        return render_template(
            "dashboard.html",
            stats=stats,
            threats=threat_data.get("threats", []),
            alerts_created=threat_data.get("alerts_created", 0),
            api_status="Connected"
        )

    except requests.RequestException as e:
        print("Dashboard API Error:", e)

        return render_template(
            "dashboard.html",
            stats={
                "total_logs": 0,
                "failed_attempts": 0,
                "active_alerts": 0,
                "total_threats": 0
            },
            threats=[],
            alerts_created=0,
            api_status="Disconnected"
        )


# 5. Security Logs
@app.route("/logs")
@login_required
def logs():

    try:
        response = requests.get(
            f"{API_URL}/security-logs",
            timeout=5
        )
        response.raise_for_status()
        data = response.json()

        return render_template(
            "logs.html",
            logs=data.get("logs", []),
            total_logs=data.get("total_logs", 0),
            api_status="Connected"
        )

    except requests.RequestException as e:
        print("Logs API Error:", e)

        return render_template(
            "logs.html",
            logs=[],
            total_logs=0,
            api_status="Disconnected"
        )


# 6. Threat Detection
@app.route("/threats")
@login_required
def threats():

    try:
        response = requests.get(
            f"{API_URL}/detect-threats",
            timeout=5
        )
        response.raise_for_status()
        data = response.json()

        return render_template(
            "threats.html",
            threats=data.get("threats", []),
            total_threats=data.get("total_threats", 0),
            alerts_created=data.get("alerts_created", 0),
            api_status="Connected"
        )

    except requests.RequestException as e:
        print("Threats API Error:", e)

        return render_template(
            "threats.html",
            threats=[],
            total_threats=0,
            alerts_created=0,
            api_status="Disconnected"
        )


# 7. Get All Alerts
@app.route("/alerts")
@login_required
def alerts():

    try:
        response = requests.get(
            f"{API_URL}/alerts",
            timeout=5
        )
        response.raise_for_status()
        data = response.json()

        return render_template(
            "alerts.html",
            alerts=data.get("alerts", []),
            total_alerts=data.get("total_alerts", 0),
            api_status="Connected"
        )

    except requests.RequestException as e:
        print("Alerts API Error:", e)

        return render_template(
            "alerts.html",
            alerts=[],
            total_alerts=0,
            api_status="Disconnected"
        )


# 8. Resolve Alert
@app.route("/resolve-alert/<int:alert_id>", methods=["POST"])
@login_required
def resolve_alert(alert_id):

    try:
        response = requests.put(
            f"{API_URL}/alerts/{alert_id}",
            params={"status": "Resolved"},
            timeout=5
        )

        response.raise_for_status()

        flash("Alert marked as Resolved successfully!", "success")
        return redirect(url_for("alerts"))

    except requests.RequestException as e:
        print("Resolve Alert API Error:", e)
        flash("Unable to update alert status.", "error")
        return redirect(url_for("alerts"))


# 9. Security Event Simulator
@app.route("/simulator", methods=["GET", "POST"])
@login_required
def simulate_event():

    if request.method == "GET":
        return render_template("simulator.html")

    ip_address = request.form.get("ip_address", "").strip()
    username = request.form.get("username", "").strip()
    status = request.form.get("status", "").strip()

    if not ip_address or not username or status not in ["Success", "Failed"]:
        flash("Please enter valid event details.", "error")
        return redirect(url_for("simulate_event"))

    try:
        response = requests.post(
            f"{API_URL}/logs",
            json={
                "ip_address": ip_address,
                "username": username,
                "event_type": "Login Attempt",
                "status": status
            },
            timeout=10
        )

        print("Simulator Status:", response.status_code)
        print("Simulator Response:", response.text)

        if response.status_code in (200, 201):

            # Run threat detection after inserting the log
            detection_response = requests.get(
                f"{API_URL}/detect-threats",
                timeout=10
            )
            detection_response.raise_for_status()

            flash("Security event submitted successfully!", "success")

        else:
            flash("Failed to submit security event.", "error")

    except requests.RequestException as e:
        print("Simulator API Error:", e)
        flash("Unable to submit event. Check FastAPI connection.", "error")

    return redirect(url_for("simulate_event"))


# 10. Logout
@app.route("/logout")
@login_required
def logout():

    session.clear()
    flash("Logged out successfully!", "success")

    return redirect(url_for("home"))


# Run Flask Application
if __name__ == "__main__":
    app.run(
        debug=True,
        port=5000
    )
