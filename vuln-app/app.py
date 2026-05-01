"""
app.py — Vulnerable Web Application (SOC Detection Lab Target)
FortiSec Operations | Autonomous SOC Detection Engine

Purpose:
    Intentionally vulnerable Flask application designed to generate
    realistic attack telemetry for SOC detection testing. Each endpoint
    simulates a real-world vulnerability class that detector.py monitors.

Vulnerabilities (by design):
    - Weak authentication (no rate limiting, plaintext credentials)
    - IDOR — Insecure Direct Object Reference on /api/user
    - Stored XSS — unsanitized comment storage and rendering
    - Broken access control — unauthenticated admin endpoint
    - C2 beaconing simulation — outbound beacon logging

WARNING:
    This application is intentionally insecure.
    DO NOT deploy in any production or internet-facing environment.
    For use in isolated lab environments only.

Author  : Solomon James
Version : 2.0.0
"""

import time
import logging

from flask import Flask, request, jsonify


# ─────────────────────────────────────────────
# APPLICATION INIT
# ─────────────────────────────────────────────

app = Flask(__name__)  # initialize Flask application instance


# ─────────────────────────────────────────────
# LOGGING CONFIGURATION
# ─────────────────────────────────────────────

# Write all log entries to app.log with timestamp prefix
# detector.py reads and parses this file for threat detection
logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"  # format: "2024-01-15 10:23:45,123 - <message>"
)


# ─────────────────────────────────────────────
# IN-MEMORY DATA STORES (intentionally weak)
# ─────────────────────────────────────────────

# Hardcoded credentials — intentionally insecure for lab telemetry generation
USERS: dict[str, str] = {
    "admin": "admin123",
    "user":  "password"
}

# Session store — no expiry, no token signing, trivially hijackable
sessions: dict[str, str] = {}

# In-memory comment store — no sanitization (XSS by design)
comments: list[str] = []

# Simulated C2 destination IP — represents attacker-controlled server
C2_DESTINATION_IP = "10.0.0.5"


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def home():
    """
    Root endpoint — confirms the vulnerable app is running.
    Used as a basic health check during lab setup.
    """
    return "Vulnerable App Running"


# ── VULNERABILITY: Weak Authentication (No rate limiting, no lockout) ──

@app.route("/login", methods=["POST"])
def login():
    """
    Login endpoint with intentionally weak authentication.

    Vulnerability class: Brute Force / Credential Stuffing
    Detection trigger : detector.py flags IPs exceeding BRUTE_FORCE_THRESHOLD
                        login attempts via "Login attempt" log pattern.

    No rate limiting, no account lockout, no CSRF protection.
    """
    username = request.form.get("username")  # read submitted username
    password = request.form.get("password")  # read submitted password
    ip       = request.remote_addr           # source IP of the request

    # Log every attempt — provides brute force telemetry for detector.py
    logging.info(f"{ip} - Login attempt: {username}")

    # Direct plaintext credential comparison — no hashing
    if USERS.get(username) == password:
        sessions["user"] = username          # store session without token signing
        return f"Welcome {username}"
    else:
        return "Login failed"


# ── VULNERABILITY: IDOR — Insecure Direct Object Reference ──

@app.route("/api/user")
def get_user():
    """
    User data API with no authorization check.

    Vulnerability class: IDOR (Insecure Direct Object Reference)
    Detection trigger : detector.py flags "User accessed ID" log events,
                        extracting the accessed ID for enumeration tracking.

    Any caller can retrieve any user's data by changing the ?id= parameter.
    No session validation is performed.
    """
    user_id = request.args.get("id")   # user-controlled ID parameter — no auth check
    ip      = request.remote_addr      # source IP for logging

    # Log the accessed ID — provides IDOR enumeration telemetry
    logging.info(f"{ip} - User accessed ID: {user_id}")

    # Static user records — simulates a real user data store
    user_data: dict[str, dict] = {
        "1": {"name": "Alice"},
        "2": {"name": "Bob"}
    }

    # Return matching record or empty dict — no ownership validation
    return jsonify(user_data.get(user_id, {}))


# ── VULNERABILITY: Stored XSS — Unsanitized Input Storage and Rendering ──

@app.route("/comment", methods=["POST"])
def comment():
    """
    Comment submission endpoint that stores raw, unsanitized input.

    Vulnerability class: Stored XSS (Cross-Site Scripting)
    Detection trigger : detector.py matches XSS payload patterns
                        (e.g. <script>, onerror=) in the "Comment submitted" log.

    Input is stored as-is and rendered directly into HTML on /comments.
    """
    text = request.form.get("text")   # raw user-supplied comment — no sanitization
    ip   = request.remote_addr        # source IP for logging

    # Log the raw comment text — enables XSS payload detection in detector.py
    logging.info(f"{ip} - Comment submitted: {text}")

    comments.append(text)             # store unsanitized comment in memory
    return "Comment added"


@app.route("/comments")
def view_comments():
    """
    Comment viewer — renders stored comments directly as raw HTML.

    Vulnerability class: Stored XSS (rendering side)
    Any script tags stored via /comment will execute here in the browser.
    No escaping or templating is applied.
    """
    return "<br>".join(comments)      # direct HTML injection — intentional for lab


# ── VULNERABILITY: Broken Access Control — Unauthenticated Admin Endpoint ──

@app.route("/admin")
def admin():
    """
    Admin panel with no authentication or authorization check.

    Vulnerability class: Broken Access Control
    Detection trigger : detector.py flags "Accessed admin panel" log events
                        as MEDIUM severity unauthorized access findings.

    Any unauthenticated request to /admin returns sensitive data.
    """
    ip = request.remote_addr          # source IP for logging

    # Log admin access — provides access control violation telemetry
    logging.info(f"{ip} - Accessed admin panel")

    return "Admin panel: sensitive data"


# ── SIMULATION: C2 Beaconing — Periodic Outbound Callback ──

@app.route("/beacon")
def beacon():
    """
    Simulates a C2 (Command & Control) beacon — periodic outbound callback.

    Vulnerability class: C2 Communication / Malware Beaconing Simulation
    Detection trigger : detector.py collects "Beaconing to <IP>" log events
                        and passes them to detect_c2_beaconing() for interval
                        consistency analysis and confidence scoring.

    In real malware, this pattern repeats at regular intervals with slight jitter.
    Simulate repeated /beacon calls to generate beaconing telemetry.
    """
    ip = request.remote_addr          # source IP of the simulated infected host

    # Log the beacon event with destination IP — consumed by C2 beaconing analyzer
    logging.info(f"{ip} - Beaconing to {C2_DESTINATION_IP}")

    return "Beacon sent"


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    # Bind to all interfaces on port 5000
    # host="0.0.0.0" makes the app reachable across the lab network
    # debug=False — prevents the interactive debugger from exposing a shell
    app.run(host="0.0.0.0", port=5000, debug=False)
