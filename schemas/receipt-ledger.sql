-- Standalone local reference only; no application database or private rows.
CREATE TABLE actions (
    action_id TEXT PRIMARY KEY,
    scope_sha256 TEXT NOT NULL,
    state TEXT NOT NULL,
    document TEXT NOT NULL
);
