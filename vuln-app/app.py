from flask import Flask, request, jsonify
import logging

app = Flask(__name__)

# Logging setup
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# Fake users
users = {
    "admin": "admin123",
    "user": "password"
}

sessions = {}

@app.route('/')
def home():
    return "Vulnerable App Running"

# LOGIN (INTENTIONALLY WEAK)
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    ip = request.remote_addr

    logging.info(f"{ip} - Login attempt: {username}")

    if users.get(username) == password:
        sessions['user'] = username
        return f"Welcome {username}"
    else:
        return "Login failed"

# IDOR API
@app.route('/api/user')
def get_user():
    user_id = request.args.get('id')
    ip = request.remote_addr

    logging.info(f"{ip} - User accessed ID: {user_id}")

    data = {
        "1": {"name": "Alice"},
        "2": {"name": "Bob"}
    }

    return jsonify(data.get(user_id, {}))

# STORED XSS
comments = []

@app.route('/comment', methods=['POST'])
def comment():
    text = request.form.get('text')
    ip = request.remote_addr

    logging.info(f"{ip} - Comment submitted: {text}")

    comments.append(text)
    return "Comment added"

@app.route('/comments')
def view_comments():
    return "<br>".join(comments)

# ADMIN (NO AUTH)
@app.route('/admin')
def admin():
    ip = request.remote_addr
    logging.info(f"{ip} - Accessed admin panel")
    return "Admin panel: sensitive data"

app.run(host='0.0.0.0', port=5000)
