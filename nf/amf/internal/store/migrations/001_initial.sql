-- AMF UE registration contexts (TS 23.501 §5.3)
-- Keyed by SUPI; TMSI indexed for GUTI-based Service Request lookup (TS 23.502 §4.2.3).
CREATE TABLE IF NOT EXISTS amf_ue_contexts (
    supi            TEXT        PRIMARY KEY,
    tmsi            BIGINT,     -- 5G-TMSI; NULL before GUTI assignment
    gmm_state       INT         NOT NULL DEFAULT 0,
    context_json    JSONB       NOT NULL,
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_activity   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS amf_ue_contexts_tmsi_idx
    ON amf_ue_contexts (tmsi) WHERE tmsi IS NOT NULL;
