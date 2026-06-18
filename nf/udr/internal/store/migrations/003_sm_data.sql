-- Session management subscription data (TS 29.503 §6.1.6.2.7 / TS 29.505)
-- One row per subscriber; sm_data holds the JSON array of per-slice
-- SessionManagementSubscriptionData entries (singleNssai + dnnConfigurations
-- with the subscribed default 5G QoS profile and session AMBR).
CREATE TABLE IF NOT EXISTS subscription_sm (
    supi       TEXT PRIMARY KEY,
    sm_data    JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
