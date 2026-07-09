package db

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL CHECK (role IN ('reader', 'admin')),
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
  secret_hash TEXT NOT NULL,
  not_before TIMESTAMP,
  expires_at TIMESTAMP,
  last_used_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  disabled_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY,
  subject_type TEXT NOT NULL CHECK (subject_type IN ('user')),
  subject_id TEXT NOT NULL,
  repository_prefix TEXT NOT NULL,
  actions TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  FOREIGN KEY(subject_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_grants_subject ON grants(subject_type, subject_id);

CREATE TABLE IF NOT EXISTS repositories (
  name TEXT PRIMARY KEY,
  tag_count INTEGER NOT NULL DEFAULT 0,
  manifest_count INTEGER NOT NULL DEFAULT 0,
  size_bytes INTEGER NOT NULL DEFAULT 0,
  last_push_at TIMESTAMP,
  last_pull_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS repository_tags (
  repository_name TEXT NOT NULL REFERENCES repositories(name) ON DELETE CASCADE,
  tag TEXT NOT NULL,
  digest TEXT NOT NULL,
  media_type TEXT NOT NULL DEFAULT '',
  size_bytes INTEGER NOT NULL DEFAULT 0,
  pushed_at TIMESTAMP NOT NULL,
  pulled_at TIMESTAMP,
  PRIMARY KEY (repository_name, tag)
);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  actor_user_id TEXT,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  result TEXT NOT NULL,
  ip_address TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at DESC);

CREATE TABLE IF NOT EXISTS usage_counters (
  id TEXT PRIMARY KEY,
  repository_name TEXT NOT NULL,
  action TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  window_start TIMESTAMP NOT NULL,
  window_end TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS signing_keys (
  id TEXT PRIMARY KEY,
  secret TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL,
  retired_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMP NOT NULL
);
`
