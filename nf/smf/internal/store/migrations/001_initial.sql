-- SMF PDU session contexts (TS 23.502 §4.3.2)
-- Keyed by sm_context_ref (UUID assigned by SMF at creation).
CREATE TABLE IF NOT EXISTS smf_sessions (
    sm_context_ref  TEXT        PRIMARY KEY,
    supi            TEXT        NOT NULL,
    dnn             TEXT        NOT NULL,
    ue_ip           TEXT        NOT NULL,
    ul_teid         BIGINT      NOT NULL,
    seid            BIGINT      NOT NULL,
    sst             INT         NOT NULL DEFAULT 1,
    sd              TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS smf_sessions_supi_idx ON smf_sessions (supi);
