-- UDR schema — TS 29.504 / TS 29.505
-- Subscriber authentication credentials (TS 29.505 §5.2.2)
CREATE TABLE IF NOT EXISTS subscription_auth (
    supi                             TEXT PRIMARY KEY,
    authentication_method            TEXT NOT NULL,
    enc_permanent_key                TEXT NOT NULL,
    protection_parameter_id          TEXT NOT NULL DEFAULT '',
    sqn                              TEXT NOT NULL,
    sqn_scheme                       TEXT NOT NULL DEFAULT 'NON_TIME_BASED',
    amf                              TEXT NOT NULL,
    algorithm_id                     TEXT NOT NULL,
    enc_opc_key                      TEXT NOT NULL DEFAULT '',
    enc_topc_key                     TEXT NOT NULL DEFAULT ''
);

-- Access and mobility subscription data (TS 29.505 §5.2.2 AMData)
CREATE TABLE IF NOT EXISTS subscription_am (
    supi                             TEXT PRIMARY KEY,
    gpsis                            JSONB NOT NULL DEFAULT '[]'::jsonb,
    snssais                          JSONB NOT NULL DEFAULT '[]'::jsonb,
    internal_group_ids               JSONB NOT NULL DEFAULT '[]'::jsonb,
    subscribed_ue_ambr_uplink        BIGINT NOT NULL DEFAULT 0,
    subscribed_ue_ambr_downlink      BIGINT NOT NULL DEFAULT 0
);

-- SMF selection subscription data (TS 29.505 §5.2.2 SmfSelectionSubscriptionData)
CREATE TABLE IF NOT EXISTS subscription_smf (
    supi                             TEXT PRIMARY KEY,
    subscribed_snssai_infos          JSONB NOT NULL DEFAULT '[]'::jsonb
);
