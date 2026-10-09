-- D13 / C-1 — purged bodies must not linger in the FTS5 index.
--
-- messages_fts is a contentful FTS5 table. Deleting a row (the purge
-- UPDATE fires messages_fts_update: delete + re-insert without the
-- body) leaves the old tokens in the index segments as delete markers
-- until a merge, and PRAGMA secure_delete only zeroes freed pages, so
-- the plaintext of a purged body stayed readable in store.db.
--
-- The FTS5 'secure-delete' option (SQLite >= 3.44) removes the entries
-- from the index on delete. It is persistent. 'rebuild' rewrites the
-- index once so residue left by earlier purges goes away too.

-- +goose Up
INSERT INTO messages_fts(messages_fts, rank) VALUES ('secure-delete', 1);
INSERT INTO messages_fts(messages_fts) VALUES ('rebuild');

-- +goose Down
INSERT INTO messages_fts(messages_fts, rank) VALUES ('secure-delete', 0);
