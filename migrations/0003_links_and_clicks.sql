CREATE TABLE links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users (id),
    slug TEXT NOT NULL UNIQUE,
    destination_url TEXT NOT NULL,
    password_hash TEXT,
    password_version INTEGER NOT NULL DEFAULT 1,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (length(slug) BETWEEN 3 AND 64)
);

CREATE INDEX links_owner_id_created_at_idx ON links (owner_id, created_at);

CREATE TABLE clicks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    link_id INTEGER NOT NULL REFERENCES links (id) ON DELETE CASCADE,
    clicked_at TEXT NOT NULL,
    ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    referer TEXT,
    device TEXT NOT NULL CHECK (device IN ('desktop', 'mobile', 'tablet', 'bot', 'unknown')),
    is_bot INTEGER NOT NULL CHECK (is_bot IN (0, 1)),
    created_at TEXT NOT NULL
);

CREATE INDEX clicks_link_id_clicked_at_idx ON clicks (link_id, clicked_at);
CREATE INDEX clicks_clicked_at_idx ON clicks (clicked_at);
