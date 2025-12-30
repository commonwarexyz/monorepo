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

-- FTS5 table for substring search (trigram tokenizer, min 3 chars)
CREATE VIRTUAL TABLE IF NOT EXISTS files_fts_substring USING fts5(
  path,
  content,
  content='files',
  content_rowid='id',
  tokenize='trigram'
);

-- FTS5 table for word search (unicode61 tokenizer)
CREATE VIRTUAL TABLE IF NOT EXISTS files_fts_word USING fts5(
  path,
  content,
  content='files',
  content_rowid='id',
  tokenize='unicode61'
);

-- Triggers to keep both FTS indexes in sync with files table
CREATE TRIGGER IF NOT EXISTS files_ai AFTER INSERT ON files BEGIN
  INSERT INTO files_fts_substring(rowid, path, content) VALUES (new.id, new.path, new.content);
  INSERT INTO files_fts_word(rowid, path, content) VALUES (new.id, new.path, new.content);
END;

CREATE TRIGGER IF NOT EXISTS files_ad AFTER DELETE ON files BEGIN
  INSERT INTO files_fts_substring(files_fts_substring, rowid, path, content) VALUES ('delete', old.id, old.path, old.content);
  INSERT INTO files_fts_word(files_fts_word, rowid, path, content) VALUES ('delete', old.id, old.path, old.content);
END;

CREATE TRIGGER IF NOT EXISTS files_au AFTER UPDATE ON files BEGIN
  INSERT INTO files_fts_substring(files_fts_substring, rowid, path, content) VALUES ('delete', old.id, old.path, old.content);
  INSERT INTO files_fts_substring(rowid, path, content) VALUES (new.id, new.path, new.content);
  INSERT INTO files_fts_word(files_fts_word, rowid, path, content) VALUES ('delete', old.id, old.path, old.content);
  INSERT INTO files_fts_word(rowid, path, content) VALUES (new.id, new.path, new.content);
END;

-- Track which versions are available
CREATE TABLE IF NOT EXISTS versions (
  version TEXT PRIMARY KEY,
  indexed_at TEXT NOT NULL DEFAULT (datetime('now'))
);
