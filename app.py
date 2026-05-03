
from flask import Flask, request, jsonify
import jwt
import datetime
import json
import os
import logging
from flask_bcrypt import Bcrypt
from functools import wraps

app = Flask(__name__)
bcrypt = Bcrypt(app)

# ── Settings ──────────────────────────────────────────────
SECRET_KEY = "supersecretkey123"
USERS_FILE = "users.json"
TOKEN_BLACKLIST = set()

# ── Task 6: Security Logging ───────────────────────────────
logging.basicConfig(
    filename="security.log",
    level=logging.WARNING,
    format="%(asctime)s - %(message)s"
)

# ── Helper Functions ───────────────────────────────────────
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

# ── Task 3: Check if token is valid ───────────────────────
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get("Authorization")

        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

        if not token:
            logging.warning(f"No token provided on route: {request.path}")
            return jsonify({"error": "Token is missing!"}), 401

        if token in TOKEN_BLACKLIST:
            logging.warning(f"Revoked token used on route: {request.path}")
            return jsonify({"error": "Token has been revoked. Please login again."}), 401

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.current_user = data
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired!"}), 401
        except jwt.InvalidTokenError:
            logging.warning(f"Invalid token used on route: {request.path}")
            return jsonify({"error": "Invalid token!"}), 401

        return f(*args, **kwargs)
    return decorated

# ── Task 4: Check if user is Admin ────────────────────────
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = request.current_user
        if user.get("role") != "admin":
            logging.warning(
                f"403 FORBIDDEN - '{user.get('username')}' tried to access {request.path}"
            )
            return jsonify({"error": "Access denied! Admins only."}), 403
        return f(*args, **kwargs)
    return decorated

# ══════════════════════════════════════════════════
# TASK 1 — Register (saves hashed password)
# ══════════════════════════════════════════════════
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")

    if not username or not password:
        return jsonify({"error": "Please provide username and password"}), 400

    users = load_users()

    if username in users:
        return jsonify({"error": "User already exists!"}), 409

    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")

    users[username] = {
        "password": hashed_pw,
        "role": role
    }
    save_users(users)

    return jsonify({"message": f"User '{username}' registered successfully!"}), 201


# ══════════════════════════════════════════════════
# TASK 2 — Login (gives back a JWT token)
# ══════════════════════════════════════════════════
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    users = load_users()

    if username not in users:
        return jsonify({"error": "Wrong username or password"}), 401

    user = users[username]

    if not bcrypt.check_password_hash(user["password"], password):
        return jsonify({"error": "Wrong username or password"}), 401

    token = jwt.encode({
        "username": username,
        "role": user["role"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }, SECRET_KEY, algorithm="HS256")

    return jsonify({"token": token}), 200


# ══════════════════════════════════════════════════
# TASK 5 — Logout (blacklists the token)
# ══════════════════════════════════════════════════
@app.route("/logout", methods=["POST"])
@token_required
def logout():
    token = request.headers.get("Authorization").split(" ")[1]
    TOKEN_BLACKLIST.add(token)
    return jsonify({"message": "Logged out! Token is now invalid."}), 200


# ══════════════════════════════════════════════════
# TASK 4a — Profile (both User and Admin can access)
# ══════════════════════════════════════════════════
@app.route("/profile", methods=["GET"])
@token_required
def profile():
    user = request.current_user
    return jsonify({
        "message": f"Hello {user['username']}! Welcome to your profile.",
        "your_role": user["role"]
    }), 200


# ══════════════════════════════════════════════════
# TASK 4b — Delete User (ONLY Admin can do this)
# ══════════════════════════════════════════════════
@app.route("/user/<user_id>", methods=["DELETE"])
@token_required
@admin_required
def delete_user(user_id):
    users = load_users()

    if user_id not in users:
        return jsonify({"error": "User not found!"}), 404

    del users[user_id]
    save_users(users)

    return jsonify({"message": f"User '{user_id}' has been deleted."}), 200


# ── Start the app ──────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True)