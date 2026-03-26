-- QuantaMrkt D1 Schema

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  github_id INTEGER UNIQUE NOT NULL,
  login TEXT NOT NULL,
  name TEXT,
  email TEXT,
  avatar_url TEXT,
  tier TEXT DEFAULT 'free' CHECK(tier IN ('free','pro','team','enterprise')),
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS models (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  author TEXT NOT NULL,
  description TEXT DEFAULT '',
  tags TEXT DEFAULT '[]',
  license TEXT DEFAULT '',
  framework TEXT DEFAULT '',
  parameters TEXT DEFAULT '',
  downloads INTEGER DEFAULT 0,
  likes INTEGER DEFAULT 0,
  verified INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS model_versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  model_id INTEGER NOT NULL REFERENCES models(id),
  version TEXT NOT NULL,
  manifest_hash TEXT,
  file_count INTEGER DEFAULT 0,
  total_size INTEGER DEFAULT 0,
  r2_manifest_key TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  UNIQUE(model_id, version)
);

CREATE TABLE IF NOT EXISTS model_files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  version_id INTEGER NOT NULL REFERENCES model_versions(id),
  filename TEXT NOT NULL,
  sha3_256_hash TEXT NOT NULL,
  size INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS signatures (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  version_id INTEGER NOT NULL REFERENCES model_versions(id),
  signer_did TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  signature_hex TEXT NOT NULL,
  attestation_type TEXT DEFAULT 'creator',
  signed_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS agents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id),
  name TEXT NOT NULL,
  did TEXT UNIQUE NOT NULL,
  algorithm TEXT NOT NULL DEFAULT 'ML-DSA-65',
  public_key_hex TEXT,
  capabilities_json TEXT DEFAULT '[]',
  status TEXT DEFAULT 'active' CHECK(status IN ('active','suspended','revoked')),
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS hndl_assessments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  model_id INTEGER NOT NULL REFERENCES models(id),
  risk_level TEXT NOT NULL,
  risk_score REAL NOT NULL,
  shelf_life_years INTEGER,
  sensitivity TEXT,
  recommendation TEXT,
  assessed_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS activity_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id),
  action TEXT NOT NULL,
  target TEXT,
  details TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_models_author ON models(author);
CREATE INDEX IF NOT EXISTS idx_models_slug ON models(slug);
CREATE INDEX IF NOT EXISTS idx_model_versions_model ON model_versions(model_id);
CREATE INDEX IF NOT EXISTS idx_signatures_version ON signatures(version_id);
CREATE INDEX IF NOT EXISTS idx_agents_user ON agents(user_id);
CREATE INDEX IF NOT EXISTS idx_agents_did ON agents(did);
CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_log(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_log(created_at);
