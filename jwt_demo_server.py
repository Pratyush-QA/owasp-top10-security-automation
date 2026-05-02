"""
jwt_demo_server.py — Minimal Flask server for JWT Security test demos.

Run before executing JWT test suite:
    pip install flask PyJWT
    python jwt_demo_server.py

Endpoints:
    POST /auth/login     → returns a signed JWT
    GET  /auth/verify    → validates Bearer token, returns 200 or 401
"""

import time
from flask import Flask, request, jsonify
import jwt

app = Flask(__name__)

SECRET_KEY = "demo-secret-key-change-in-production"
ISSUER = "demo-server"
VALID_USERS = {"admin": "password123", "user": "userpass"}


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if VALID_USERS.get(username) != password:
        return jsonify({"error": "Invalid credentials"}), 401

    payload = {
        "userId": 1 if username == "admin" else 2,
        "username": username,
        "role": "admin" if username == "admin" else "user",
        "iss": ISSUER,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,   # 1 hour expiry
        "tokenType": "USER_TOKEN",
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return jsonify({"token": token})


@app.route("/auth/verify", methods=["GET"])
def verify():
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    token = auth_header[len("Bearer "):]

    if not token or token.isspace():
        return jsonify({"error": "Empty token"}), 401

    # Explicitly reject alg:none — NEVER allow unsigned tokens
    try:
        unverified_header = jwt.get_unverified_header(token)
        if unverified_header.get("alg", "").lower() == "none":
            return jsonify({"error": "alg:none is not permitted"}), 401
    except Exception:
        return jsonify({"error": "Invalid token format"}), 401

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"],    # only allow HS256 — never "none"
            issuer=ISSUER,           # validate issuer
            options={"require": ["exp", "iss", "iat"]},
        )
        return jsonify({"message": "Token valid", "userId": payload.get("userId")}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 401
    except jwt.InvalidIssuerError:
        return jsonify({"error": "Invalid token issuer"}), 401
    except jwt.InvalidSignatureError:
        return jsonify({"error": "Invalid token signature"}), 401
    except jwt.DecodeError:
        return jsonify({"error": "Token decode error"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 401


if __name__ == "__main__":
    print("JWT Demo Server running at http://localhost:5050")
    print("Login:  POST /auth/login  with {username, password}")
    print("Verify: GET  /auth/verify with Authorization: Bearer <token>")
    app.run(host="0.0.0.0", port=5050, debug=False)
