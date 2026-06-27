-- Addison Garden — shared grow state (one row, id = 1)
-- Apply with:  wrangler d1 execute addison-garden --remote --file=schema.sql

CREATE TABLE IF NOT EXISTS grow_state (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  rev        INTEGER NOT NULL DEFAULT 0,
  data       TEXT    NOT NULL DEFAULT '{}',
  updated_at TEXT
);

-- Seed the single row (no-op if it already exists)
INSERT OR IGNORE INTO grow_state (id, rev, data) VALUES (1, 0, '{}');
