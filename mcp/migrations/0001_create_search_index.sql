-- Search index schema using FTS5 for full-text search
-- Files are stored per-version since versioned content is immutable

-- Main files table storing file metadata and content
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  version TEXT NOT NULL,
  path TEXT NOT NULL,
  content TEXT NOT NULL,
  UNIQUE(version, path)
);

-- Index for quick version lookups
CREATE INDEX IF NOT EXISTS idx_files_version ON files(version);

-- FTS5 virtual table for full-text search
-- Uses external content to avoid duplicating the content column
-- Trigram tokenizer enables substring matching (minimum 3 characters)
CREATE VIRTUAL TABLE IF NOT EXISTS files_fts USING fts5(
  path,
  content,
  content='files',
  content_rowid='id',
  tokenize='trigram'
);

-- Triggers to keep FTS index in sync with files table
CREATE TRIGGER IF NOT EXISTS files_ai AFTER INSERT ON files BEGIN
  INSERT INTO files_fts(rowid, path, content) VALUES (new.id, new.path, new.content);
END;

CREATE TRIGGER IF NOT EXISTS files_ad AFTER DELETE ON files BEGIN
  INSERT INTO files_fts(files_fts, rowid, path, content) VALUES ('delete', old.id, old.path, old.content);
END;

CREATE TRIGGER IF NOT EXISTS files_au AFTER UPDATE ON files BEGIN
  INSERT INTO files_fts(files_fts, rowid, path, content) VALUES ('delete', old.id, old.path, old.content);
  INSERT INTO files_fts(rowid, path, content) VALUES (new.id, new.path, new.content);
END;

-- Track which versions are available
CREATE TABLE IF NOT EXISTS versions (
  version TEXT PRIMARY KEY,
  indexed_at TEXT NOT NULL DEFAULT (datetime('now'))
);
