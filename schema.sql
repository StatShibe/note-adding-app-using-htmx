CREATE TABLE IF NOT EXISTS login_details (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
    note_id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_username TEXT NOT NULL,
    content TEXT,
    posted_at_time TIMESTAMP NOT NULL,
    label TEXT
);