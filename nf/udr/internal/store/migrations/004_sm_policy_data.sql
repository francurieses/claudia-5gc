-- SM Policy Data (TS 29.519 §5.6.2.4 / TS 29.504 §5.2.13)
-- One row per subscriber; data holds the JSON SmPolicyData object
-- (smPolicySnssaiData map → per-S-NSSAI smPolicyDnnData with the authorized
-- default 5QI / ARP / Session-AMBR per DNN). Retrieved by the PCF over N36.
CREATE TABLE IF NOT EXISTS subscription_sm_policy (
    supi       TEXT PRIMARY KEY,
    data       JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
