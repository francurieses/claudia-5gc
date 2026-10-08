-- Per (S-NSSAI, DNN) subscribed Session-AMBR (UDR-003, non-3GPP store of record).
-- Ref: TS 23.501 §5.7.2.6 (subscribed Session-AMBR), TS 29.503 §6.1.6.2.9
-- (DnnConfiguration.sessionAmbr), TS 29.571 §5.5.2 (BitRate strings).
-- sd '' = slice without SD; lower-case hex otherwise. source = origin of the
-- effective value; seed_* = what the seed would produce (restored by revert).
CREATE TABLE IF NOT EXISTS slice_dnn_qos (
    sst             SMALLINT    NOT NULL CHECK (sst BETWEEN 0 AND 255),
    sd              TEXT        NOT NULL DEFAULT '' CHECK (sd = '' OR sd ~ '^[0-9a-f]{6}$'),
    dnn             TEXT        NOT NULL CHECK (dnn <> ''),
    session_ambr_ul TEXT        NOT NULL,
    session_ambr_dl TEXT        NOT NULL,
    source          TEXT        NOT NULL CHECK (source IN ('default','operator','edited')),
    seed_ambr_ul    TEXT        NOT NULL,
    seed_ambr_dl    TEXT        NOT NULL,
    seed_source     TEXT        NOT NULL CHECK (seed_source IN ('default','operator')),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (sst, sd, dnn)
);
