"""Recipe Box API — BE104 course skeleton.

A working Flask + SQLite CRUD API for recipes. It stores data perfectly —
and it trusts everyone. There is no authentication and no authorization yet.
That is the point: you will add both, lesson by lesson, in Units 2 and 3.
"""

import os
import sqlite3
from datetime import datetime, timedelta, timezone

import jwt
from dotenv import load_dotenv
from flask import Flask, g, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

DATABASE = "recipes.db"

JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is not set — check your .env file")

app = Flask(__name__)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def recipe_to_dict(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "ingredients": row["ingredients"],
        "instructions": row["instructions"],
        "is_public": bool(row["is_public"]),
    }


@app.get("/")
def hello():
    return jsonify({"message": "Recipe Box API", "recipes": "/recipes"})


@app.get("/recipes")
def list_recipes():
    rows = get_db().execute("SELECT * FROM recipes ORDER BY id").fetchall()
    return jsonify([recipe_to_dict(r) for r in rows])


@app.get("/recipes/<int:recipe_id>")
def get_recipe(recipe_id):
    row = get_db().execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404

    # Public recipes are readable by anyone.
    if row["is_public"]:
        return jsonify(recipe_to_dict(row))

    # Private recipe: only the owner may read it. Authentication is
    # optional here, so a missing/invalid token just means "not the owner".
    user_id = None
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        try:
            payload = jwt.decode(parts[1], JWT_SECRET, algorithms=["HS256"])
            user_id = int(payload["sub"])
        except (jwt.PyJWTError, KeyError, ValueError):
            user_id = None  # bad/expired token -> treat as anonymous

    if user_id is not None and row["owner_id"] == user_id:
        return jsonify(recipe_to_dict(row))

    # Not public, and not the owner (or not logged in): hide its existence.
    return jsonify({"error": "recipe not found"}), 404


@app.post("/recipes")
def create_recipe():
    # 1–2: require a well-formed Authorization: Bearer <token> header.
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return jsonify({"error": "missing or invalid authorization header"}), 401
    token = parts[1]

    # 3: verify signature + expiry. Expired gets its own clear message.
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "token expired, please log in again"}), 401
    except jwt.PyJWTError:
        return jsonify({"error": "invalid token"}), 401

    user_id = payload.get("sub")
    if not user_id:
        return jsonify({"error": "invalid token payload"}), 401
    g.user_id = user_id

    data = request.get_json(silent=True)
    if not data or not data.get("title") or not data.get("ingredients"):
        return jsonify({"error": "title and ingredients are required"}), 400
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO recipes (title, ingredients, instructions, is_public, owner_id)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                data["title"],
                data["ingredients"],
                data.get("instructions", ""),
                1 if data.get("is_public", True) else 0,
                int(g.user_id),  # from the verified token — never the client body
            ),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (cur.lastrowid,)
    ).fetchone()
    return jsonify(recipe_to_dict(row)), 201

@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    # Input validation: missing or empty fields → 400 Bad Request
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    db = get_db()
    row = db.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    # Same 401 for "user not found" and "wrong password" — no enumeration hint.
    if row is None or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "invalid credentials"}), 401

    # Identity confirmed. Issue a signed, short-lived JWT.
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "sub": str(row["id"]),
            "username": row["username"],
            "iat": now,
            "exp": now + timedelta(minutes=15),
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    return jsonify({"token": token, "token_type": "Bearer"}), 200

@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    # Basic validation: all fields required
    if not username or not email or not password:
        return jsonify({"error": "username, email, and password are required"}), 400

    # 1) hash the password – never store or return the raw password
    password_hash = generate_password_hash(password)

    db = get_db()
    try:
        # 2) insert the user with the hash, using parameterized SQL
        cur = db.execute(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (?, ?, ?)
            """,
            (username, email, password_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        # username or email already in use
        return jsonify({"error": "username or email already registered"}), 409

    # 3) return a safe response (no password fields)
    return (
        jsonify(
            {
                "id": cur.lastrowid,
                "username": username,
                "email": email,
            }
        ),
        201,
    )

@app.patch("/recipes/<int:recipe_id>")
def update_recipe(recipe_id):
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return jsonify({"error": "missing or invalid authorization header"}), 401
    token = parts[1]

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "token expired, please log in again"}), 401
    except jwt.PyJWTError:
        return jsonify({"error": "invalid token"}), 401

    user_id = payload.get("sub")
    if not user_id:
        return jsonify({"error": "invalid token payload"}), 401
    g.user_id = user_id

    db = get_db()

    # 1) Load the recipe
    row = db.execute(
        "SELECT id, owner_id FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404

    # 2) Ownership check
    if row["owner_id"] != int(g.user_id):
        return jsonify({"error": "forbidden: you do not own this recipe"}), 403

    # 3) Now it's safe to update
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "a JSON body is required"}), 400
    fields, values = [], []
    for column in ("title", "ingredients", "instructions"):
        if column in data:
            fields.append(f"{column} = ?")
            values.append(data[column])
    if "is_public" in data:
        fields.append("is_public = ?")
        values.append(1 if data["is_public"] else 0)
    if not fields:
        return jsonify({"error": "nothing to update"}), 400
    values.append(recipe_id)
    try:
        db.execute(f"UPDATE recipes SET {', '.join(fields)} WHERE id = ?", values)
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409
    row = db.execute("SELECT * FROM recipes WHERE id = ?", (recipe_id,)).fetchone()
    return jsonify(recipe_to_dict(row))


@app.delete("/recipes/<int:recipe_id>")
def delete_recipe(recipe_id):
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return jsonify({"error": "missing or invalid authorization header"}), 401
    token = parts[1]

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        return jsonify({"error": "invalid or expired token"}), 401

    user_id = payload.get("sub")
    if not user_id:
        return jsonify({"error": "invalid token payload"}), 401
    g.user_id = user_id

    db = get_db()

    # 1) Load the recipe
    row = db.execute(
        "SELECT id, owner_id FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404

    # 2) Ownership check
    if row["owner_id"] != int(g.user_id):
        return jsonify({"error": "forbidden: you do not own this recipe"}), 403

    # 3) Now it's safe to delete
    db.execute("DELETE FROM recipes WHERE id = ?", (recipe_id,))
    db.commit()
    return "", 204

if __name__ == "__main__":
    app.run(debug=False)