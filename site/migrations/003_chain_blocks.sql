-- PQC Block Chain: certificate transparency log with block headers,
-- Merkle trees, and ML-DSA signatures

CREATE TABLE IF NOT EXISTS chain_blocks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  block_number INTEGER UNIQUE NOT NULL,
  timestamp TEXT NOT NULL,
  previous_block_hash TEXT NOT NULL,
  merkle_root TEXT NOT NULL,
  entries_count INTEGER NOT NULL,
  entry_range_start INTEGER NOT NULL,
  entry_range_end INTEGER NOT NULL,
  block_hash TEXT NOT NULL,
  signature TEXT,
  signer_did TEXT DEFAULT 'did:web:quantamrkt.com:chain:authority'
);

CREATE INDEX IF NOT EXISTS idx_blocks_number ON chain_blocks(block_number);
CREATE INDEX IF NOT EXISTS idx_blocks_hash ON chain_blocks(block_hash);
