-- Failed claim attempts, per owner.
--
-- Rate limiting has to count the person guessing, not the devices guessed at:
-- a per-device counter lets anyone lock every unclaimed node in the system by
-- submitting wrong codes.

CREATE TABLE IF NOT EXISTS claim_attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id     TEXT NOT NULL,
    attempted_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_claim_attempts_owner ON claim_attempts(owner_id, attempted_at);
