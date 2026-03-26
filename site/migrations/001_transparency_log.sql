-- Transparency Log: append-only, hash-chained, publicly auditable
-- Each entry chains to the previous via SHA-256, forming a verifiable log

CREATE TABLE IF NOT EXISTS transparency_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sequence_number INTEGER UNIQUE NOT NULL,
  timestamp TEXT NOT NULL DEFAULT (datetime('now')),
  action TEXT NOT NULL,           -- 'model:signed', 'model:verified', 'agent:registered', 'agent:revoked', 'manifest:pushed'
  actor_did TEXT,                 -- DID of the signer/actor
  target_type TEXT NOT NULL,      -- 'model', 'agent', 'manifest'
  target_id TEXT NOT NULL,        -- slug or DID
  payload_hash TEXT NOT NULL,     -- SHA-256 of the action payload
  previous_hash TEXT NOT NULL,    -- hash of previous log entry (chain link)
  merkle_root TEXT,               -- current Merkle root after this entry
  signature TEXT,                 -- ML-DSA signature of this entry by the platform key
  metadata TEXT DEFAULT '{}'      -- JSON with additional context
);

CREATE INDEX IF NOT EXISTS idx_tlog_sequence ON transparency_log(sequence_number);
CREATE INDEX IF NOT EXISTS idx_tlog_target ON transparency_log(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_tlog_action ON transparency_log(action);
CREATE INDEX IF NOT EXISTS idx_tlog_timestamp ON transparency_log(timestamp);
