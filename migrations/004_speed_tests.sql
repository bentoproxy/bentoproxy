-- Results of owner-triggered speed tests.
--
-- Tests never run on their own: a node lives on someone's home connection, so
-- unrequested transfers would add traffic they did not ask for. Keeping the
-- results lets the dashboard show the last measurement without re-running one.

CREATE TABLE IF NOT EXISTS speed_tests (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   TEXT NOT NULL,
    ran_at      INTEGER NOT NULL,
    bytes       INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    down_bps    INTEGER NOT NULL DEFAULT 0,
    ok          INTEGER NOT NULL DEFAULT 0,
    error       TEXT,
    FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_speed_tests_device ON speed_tests(device_id, ran_at);
