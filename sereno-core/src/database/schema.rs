/// Database schema for Sereno
pub const SCHEMA: &str = r#"
-- Rules table
CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 0,
    action TEXT NOT NULL CHECK (action IN ('allow', 'deny', 'ask')),
    conditions TEXT NOT NULL,
    validity TEXT NOT NULL,
    hit_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    profile_id TEXT,
    FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_rules_priority ON rules(priority DESC);
CREATE INDEX IF NOT EXISTS idx_rules_profile ON rules(profile_id);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);

-- Profiles table
CREATE TABLE IF NOT EXISTS profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 0,
    silent_mode TEXT CHECK (silent_mode IN ('allow_all', 'deny_all', NULL)),
    created_at TEXT NOT NULL
);

-- Connections log table
CREATE TABLE IF NOT EXISTS connections (
    id TEXT PRIMARY KEY,
    process_path TEXT NOT NULL,
    process_name TEXT NOT NULL,
    process_id INTEGER NOT NULL,
    remote_address TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    local_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    direction TEXT NOT NULL,
    domain TEXT,
    country TEXT,
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,
    allowed INTEGER NOT NULL,
    rule_id TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_connections_started ON connections(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_connections_process ON connections(process_path);
CREATE INDEX IF NOT EXISTS idx_connections_allowed ON connections(allowed);
CREATE INDEX IF NOT EXISTS idx_connections_domain ON connections(domain);

-- Settings table for app configuration
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;
