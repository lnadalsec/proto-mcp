-- Link messages_fts to messages by an integer rowid instead of the
-- UNINDEXED message_id column.
--
-- Before: every trigger ran `DELETE FROM messages_fts WHERE message_id
-- = OLD.id`, and Search ordered by `(SELECT rank FROM messages_fts
-- WHERE message_id = messages.id)`. message_id is UNINDEXED, so each of
-- those was a full scan of the FTS table — O(N²) over a backfill — and
-- rank is NULL outside a MATCH, so results were never relevance-ordered.
--
-- messages has a TEXT primary key, so its implicit rowid is not stable
-- (VACUUM may renumber it, and `protonmcp purge --vacuum` runs one).
-- messages_fts_map gives each message a stable INTEGER PRIMARY KEY that
-- is used as the FTS rowid; every lookup in either direction is then
-- an index seek.
--
-- The UPDATE trigger now only fires when an indexed column actually
-- changes value, so flag-only updates (unread, starred, folder) and
-- no-op envelope upserts during a backfill no longer re-index the row.
--
-- D13 / C-1: the old FTS table is dropped (its pages are zeroed by the
-- secure_delete pragma) and the new one gets the FTS5 'secure-delete'
-- option before any row is inserted, as migration 0007 did.

-- +goose Up
DROP TRIGGER IF EXISTS messages_fts_insert;
DROP TRIGGER IF EXISTS messages_fts_delete;
DROP TRIGGER IF EXISTS messages_fts_update;
DROP TABLE IF EXISTS messages_fts;

CREATE TABLE messages_fts_map (
    fts_rowid  INTEGER PRIMARY KEY,
    message_id TEXT NOT NULL UNIQUE
);

CREATE VIRTUAL TABLE messages_fts USING fts5(
    subject,
    from_address,
    from_name,
    to_addresses,
    body_text,
    tokenize = 'porter unicode61'
);

INSERT INTO messages_fts(messages_fts, rank) VALUES ('secure-delete', 1);

INSERT INTO messages_fts_map(message_id) SELECT id FROM messages;

INSERT INTO messages_fts(rowid, subject, from_address, from_name, to_addresses, body_text)
SELECT map.fts_rowid, m.subject, m.from_address, m.from_name, m.to_json, m.body_text
  FROM messages m JOIN messages_fts_map map ON map.message_id = m.id;

-- +goose StatementBegin
CREATE TRIGGER messages_fts_insert AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts_map(message_id) VALUES (NEW.id);
    INSERT INTO messages_fts(rowid, subject, from_address, from_name, to_addresses, body_text)
    VALUES ((SELECT fts_rowid FROM messages_fts_map WHERE message_id = NEW.id),
            NEW.subject, NEW.from_address, NEW.from_name, NEW.to_json, NEW.body_text);
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER messages_fts_delete AFTER DELETE ON messages BEGIN
    DELETE FROM messages_fts
     WHERE rowid = (SELECT fts_rowid FROM messages_fts_map WHERE message_id = OLD.id);
    DELETE FROM messages_fts_map WHERE message_id = OLD.id;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER messages_fts_update
AFTER UPDATE OF id, subject, from_address, from_name, to_json, body_text ON messages
WHEN OLD.id IS NOT NEW.id
  OR OLD.subject IS NOT NEW.subject
  OR OLD.from_address IS NOT NEW.from_address
  OR OLD.from_name IS NOT NEW.from_name
  OR OLD.to_json IS NOT NEW.to_json
  OR OLD.body_text IS NOT NEW.body_text
BEGIN
    UPDATE messages_fts_map SET message_id = NEW.id WHERE message_id = OLD.id;
    DELETE FROM messages_fts
     WHERE rowid = (SELECT fts_rowid FROM messages_fts_map WHERE message_id = NEW.id);
    INSERT INTO messages_fts(rowid, subject, from_address, from_name, to_addresses, body_text)
    VALUES ((SELECT fts_rowid FROM messages_fts_map WHERE message_id = NEW.id),
            NEW.subject, NEW.from_address, NEW.from_name, NEW.to_json, NEW.body_text);
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS messages_fts_insert;
DROP TRIGGER IF EXISTS messages_fts_delete;
DROP TRIGGER IF EXISTS messages_fts_update;
DROP TABLE IF EXISTS messages_fts;
DROP TABLE IF EXISTS messages_fts_map;

CREATE VIRTUAL TABLE messages_fts USING fts5(
    message_id UNINDEXED,
    subject,
    from_address,
    from_name,
    to_addresses,
    body_text,
    tokenize = 'porter unicode61'
);

INSERT INTO messages_fts(messages_fts, rank) VALUES ('secure-delete', 1);

INSERT INTO messages_fts(message_id, subject, from_address, from_name, to_addresses, body_text)
SELECT id, subject, from_address, from_name, to_json, body_text FROM messages;

-- +goose StatementBegin
CREATE TRIGGER messages_fts_insert AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(message_id, subject, from_address, from_name, to_addresses, body_text)
    VALUES (NEW.id, NEW.subject, NEW.from_address, NEW.from_name, NEW.to_json, NEW.body_text);
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER messages_fts_delete AFTER DELETE ON messages BEGIN
    DELETE FROM messages_fts WHERE message_id = OLD.id;
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER messages_fts_update AFTER UPDATE ON messages BEGIN
    DELETE FROM messages_fts WHERE message_id = OLD.id;
    INSERT INTO messages_fts(message_id, subject, from_address, from_name, to_addresses, body_text)
    VALUES (NEW.id, NEW.subject, NEW.from_address, NEW.from_name, NEW.to_json, NEW.body_text);
END;
-- +goose StatementEnd
