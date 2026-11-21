package oauth2

import "os"

// DefaultDevSecret is the lab-only HS256 signing secret shared by the NRF
// (issuer) and every token verifier when nothing else is configured.
// MUST be overridden (OAUTH2_SECRET) outside development.
// Ref: TS 33.501 §13.4.1.
const DefaultDevSecret = "5gc-dev-oauth2-secret-change-in-production" //nolint:gosec // G101: public lab default, overridden by OAUTH2_SECRET; key management is SEC-001

// SecretEnv is the environment variable that overrides the configured secret.
const SecretEnv = "OAUTH2_SECRET" //nolint:gosec // G101: env var name, not a credential

// ResolveSecret returns the effective HS256 secret. Precedence: non-empty
// OAUTH2_SECRET env var, then the non-empty configured value, then
// DefaultDevSecret.
func ResolveSecret(configured string) string {
	if v := os.Getenv(SecretEnv); v != "" {
		return v
	}
	if configured != "" {
		return configured
	}
	return DefaultDevSecret
}
