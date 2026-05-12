const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DB_PATH = path.join(__dirname, '..', 'data', 'rugwatch.db');

// Ensure data directory exists
const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(DB_PATH);

// Enable WAL mode for better concurrent access
db.pragma('journal_mode = WAL');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    contract_address TEXT NOT NULL,
    chain TEXT DEFAULT 'solana',
    token_name TEXT,
    token_symbol TEXT,
    status TEXT DEFAULT 'pending',
    risk_score REAL,
    risk_level TEXT,
    summary TEXT,
    details TEXT,
    created_at INTEGER DEFAULT (unixepoch()),
    completed_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS scan_results (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT DEFAULT 'info',
    title TEXT NOT NULL,
    description TEXT,
    passed INTEGER DEFAULT 0,
    details TEXT,
    created_at INTEGER DEFAULT (unixepoch()),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
  );

  CREATE TABLE IF NOT EXISTS api_keys (
    key TEXT PRIMARY KEY,
    name TEXT,
    active INTEGER DEFAULT 1,
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    status TEXT DEFAULT 'idle',
    config TEXT,
    last_seen INTEGER,
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE INDEX IF NOT EXISTS idx_scans_contract ON scans(contract_address);
  CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
  CREATE INDEX IF NOT EXISTS idx_scan_results_scan ON scan_results(scan_id);
`);

// ─── Security Events (persistent memory — never wiped) ───
db.exec(`
  CREATE TABLE IF NOT EXISTS security_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    direction TEXT DEFAULT 'ingress',
    rule TEXT,
    message TEXT,
    risk_score REAL DEFAULT 0,
    intent_category TEXT,
    intent_confidence REAL DEFAULT 0,
    layer TEXT DEFAULT 'keyword',
    metadata TEXT,
    created_at INTEGER DEFAULT (unixepoch())
  );
  CREATE INDEX IF NOT EXISTS idx_security_events_time ON security_events(timestamp);
  CREATE INDEX IF NOT EXISTS idx_security_events_action ON security_events(action);
  CREATE INDEX IF NOT EXISTS idx_security_events_category ON security_events(intent_category);
`);

module.exports = db;
