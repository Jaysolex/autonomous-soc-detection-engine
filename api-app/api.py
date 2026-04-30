from flask import Flask, request, jsonify
import logging
import base64

app = Flask(__name__)

# =========================
# LOGGING CONFIG (SHARED)
# =========================
logging.basicConfig(
    filename='../vuln-app/app.log',  # SAME log file as web app
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# =========================
# FAKE DATABASE
# =========================
users = {
    "1": {"user": "alice", "role": "user"},
    "2": {"user": "bob", "role": "user"},
    "999": {"user": "admin", "role": "admin"}
}

orders = {
    "1": {"item": "Laptop", "owner": "1"},
    "2": {"item": "Phone", "owner": "2"}
}

# =========================
# HELPER: FAKE TOKEN (INSECURE)
# =========================
def decode_token(token):
    try:
        decoded = base64.b64decode(token).decode()
        return decoded  # NO VALIDATION (VULNERABLE)
    except:
        return None

# =========================
# ROUTE 1 — BROKEN AUTH
# =========================
@app.route('/api/login', methods=['POST'])
def login():
    username = request.form.get('username')
    ip = request.remote_addr

    # Fake token (no password check)
    token = base64.b64encode(username.encode()).decode()

    logging.info(f"{ip} - API Login issued token for user: {username}")

    return jsonify({"token": token})

# =========================
# ROUTE 2 — TOKEN ABUSE
# =========================
@app.route('/api/profile')
def profile():
    token = request.headers.get('Authorization')
    ip = request.remote_addr

    user = decode_token(token)

    logging.info(f"{ip} - Token used: {token} decoded as {user}")

    return jsonify({
        "user": user,
        "role": users.get(user, {}).get("role", "unknown")
    })

# =========================
# ROUTE 3 — IDOR (API)
# =========================
@app.route('/api/orders')
def get_orders():
    order_id = request.args.get('id')
    token = request.headers.get('Authorization')
    ip = request.remote_addr

    user = decode_token(token)

    logging.info(f"{ip} - API IDOR attempt by {user} accessing order {order_id}")

    return jsonify(orders.get(order_id, {}))

# =========================
# ROUTE 4 — ADMIN BYPASS
# =========================
@app.route('/api/admin')
def admin():
    token = request.headers.get('Authorization')
    ip = request.remote_addr

    user = decode_token(token)

    logging.info(f"{ip} - Admin endpoint accessed using token: {token} (user: {user})")

    if user == "999":  # attacker can forge this
        return "Admin access granted"
    else:
        return "Access denied"

# =========================
# START APP
# =========================
app.run(host='0.0.0.0', port=5001)
