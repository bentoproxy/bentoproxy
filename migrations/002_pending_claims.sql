-- Devices that have network access but no owner yet.
--
-- A node announces itself here on first boot, carrying the setup code printed
-- on its case. The owner types that code into their dashboard, which binds the
-- node to their account and leaves the issued credentials for the node to
-- collect. This way the token never passes through the owner's hands.

CREATE TABLE IF NOT EXISTS pending_claims (
    hw_id       TEXT PRIMARY KEY,   -- stable, device-derived (its MAC)
    claim_code  TEXT NOT NULL,      -- the code printed on the device
    model       TEXT,               -- e.g. esp32s3, for display
    device_id   TEXT,               -- set once an owner claims it
    token       TEXT,               -- set once an owner claims it
    created_at  INTEGER NOT NULL,
    announced_at INTEGER NOT NULL,  -- refreshed on every announce
    claimed_at  INTEGER
);

-- Owners claim by code alone, so this lookup must be fast.
CREATE INDEX IF NOT EXISTS idx_pending_claims_code ON pending_claims(claim_code);
CREATE INDEX IF NOT EXISTS idx_pending_claims_announced ON pending_claims(announced_at);
