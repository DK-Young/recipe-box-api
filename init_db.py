"""Create and seed recipes.db. Run once after cloning: python init_db.py"""

import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS recipes (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL UNIQUE,
    ingredients TEXT NOT NULL,
    instructions TEXT NOT NULL DEFAULT '',
    is_public INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);
"""

SEED = [
    (
        "Shakshuka",
        "eggs, tomatoes, peppers, onion, cumin, paprika",
        "Simmer the sauce, crack in the eggs, cover until just set.",
        1,
    ),
    (
        "Overnight oats",
        "rolled oats, milk, yogurt, chia seeds, honey",
        "Stir everything together and refrigerate overnight.",
        1,
    ),
    (
        "Secret family hot sauce",
        "habaneros, garlic, vinegar, a secret ingredient",
        "If we wrote it down here, it wouldn't be a secret.",
        0,
    ),
]

connection = sqlite3.connect("recipes.db")
print("SCHEMA being executed:")
print(SCHEMA)
print("------")
connection.executescript(SCHEMA)
existing = connection.execute("SELECT COUNT(*) FROM recipes").fetchone()[0]
if existing == 0:
    connection.executemany(
        "INSERT INTO recipes (title, ingredients, instructions, is_public)"
        " VALUES (?, ?, ?, ?)",
        SEED,
    )
    connection.commit()
    print(f"Created recipes.db and seeded {len(SEED)} recipes.")
else:
    print(f"recipes.db already has {existing} recipes - nothing to do.")
connection.close()
