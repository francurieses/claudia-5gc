-- Forward-compat (REL19-7.2, expand/contract: additive only). schema_version
-- records which release wrote the row; extra keeps record keys written by a
-- newer release so an older SMF's read-modify-write does not drop them.
ALTER TABLE smf_sessions ADD COLUMN IF NOT EXISTS schema_version INT NOT NULL DEFAULT 0;
ALTER TABLE smf_sessions ADD COLUMN IF NOT EXISTS extra JSONB NOT NULL DEFAULT '{}'::jsonb;
