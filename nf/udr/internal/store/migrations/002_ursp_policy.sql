-- UE Policy subscription data (TS 29.525 / TS 24.526)
-- Stores per-subscriber URSP rule sets. Rows with supi IS NULL are operator defaults.
CREATE TABLE IF NOT EXISTS subscription_policy (
    id         TEXT PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    supi       TEXT,
    precedence INT NOT NULL DEFAULT 100,
    rules_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_subscription_policy_supi
    ON subscription_policy (supi);
