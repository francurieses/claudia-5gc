package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsAreReadOnlyAndSafe(t *testing.T) {
	cfg, err := Load(writeConfig(t, "transport: sse\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.AccessMode != "read-only" {
		t.Errorf("access_mode default: got %q, want read-only", cfg.AccessMode)
	}
	if cfg.AllowServiceControl {
		t.Error("allow_service_control must default to false")
	}
	if cfg.Guardrails.MinIntervalMs != 2000 || cfg.Guardrails.MaxResultBytes != 256<<10 {
		t.Errorf("guardrail defaults: %+v", cfg.Guardrails)
	}
	if cfg.LokiAddr != "http://loki:3100" {
		t.Errorf("loki_addr default: got %q", cfg.LokiAddr)
	}
}

func TestInvalidAccessModeFails(t *testing.T) {
	if _, err := Load(writeConfig(t, "access_mode: root\n")); err == nil {
		t.Fatal("expected validation error for access_mode root")
	}
}

func TestInvalidTokenRoleFails(t *testing.T) {
	body := "auth:\n  tokens:\n    - token: abc\n      role: superuser\n"
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("expected validation error for unknown role")
	}
}

func TestBearerTokenEnvMapsToOperator(t *testing.T) {
	t.Setenv("MCP_BEARER_TOKEN", "op-secret")
	cfg, err := Load(writeConfig(t, "transport: sse\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.Auth.Enabled() || cfg.Auth.BearerToken != "op-secret" {
		t.Errorf("bearer token not applied: %+v", cfg.Auth)
	}
}

func TestRoleTokensFromEnv(t *testing.T) {
	t.Setenv("MCP_TOKEN_VIEWER", "v")
	t.Setenv("MCP_TOKEN_ADMIN", "a")
	cfg, err := Load(writeConfig(t, "transport: sse\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	roles := map[string]string{}
	for _, tok := range cfg.Auth.Tokens {
		roles[tok.Token] = tok.Role
	}
	if roles["v"] != "viewer" || roles["a"] != "admin" {
		t.Errorf("env tokens: %+v", cfg.Auth.Tokens)
	}
}

func TestAccessModeEnvOverride(t *testing.T) {
	t.Setenv("MCP_ACCESS_MODE", "LAB")
	cfg, err := Load(writeConfig(t, "transport: sse\naccess_mode: read-only\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.AccessMode != "lab" {
		t.Errorf("env override: got %q", cfg.AccessMode)
	}
}

func TestMetricsHostOverride(t *testing.T) {
	cfg, err := Load(writeConfig(t, "transport: sse\n"))
	if err != nil || cfg.MetricsHostOverride != "" {
		t.Fatalf("default: %q, %v", cfg.MetricsHostOverride, err)
	}
	cfg, err = Load(writeConfig(t, "transport: sse\nmetrics_host_override: localhost\n"))
	if err != nil || cfg.MetricsHostOverride != "localhost" {
		t.Fatalf("yaml: %+v, %v", cfg, err)
	}
	t.Setenv("MCP_METRICS_HOST_OVERRIDE", "127.0.0.1")
	cfg, err = Load(writeConfig(t, "transport: sse\nmetrics_host_override: localhost\n"))
	if err != nil || cfg.MetricsHostOverride != "127.0.0.1" {
		t.Fatalf("env: %+v, %v", cfg, err)
	}
	t.Setenv("MCP_METRICS_HOST_OVERRIDE", "http://evil:80")
	if _, err := Load(writeConfig(t, "transport: sse\n")); err == nil {
		t.Fatal("expected validation error for a host with scheme/port")
	}
}

func TestBSFAddrDefaultAndEnv(t *testing.T) {
	cfg, err := Load(writeConfig(t, "transport: sse\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.BSFAddr != "https://bsf:8010" {
		t.Errorf("bsf_addr default: got %q", cfg.BSFAddr)
	}
	t.Setenv("BSF_ADDR", "https://localhost:8010")
	cfg, err = Load(writeConfig(t, "transport: sse\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.BSFAddr != "https://localhost:8010" {
		t.Errorf("bsf_addr env: got %q", cfg.BSFAddr)
	}
}

func TestNEFAndSMSFAddrDefaultAndEnv(t *testing.T) {
	cfg, err := Load(writeConfig(t, "transport: sse\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.NEFAddr != "https://nef:8011" || cfg.SMSFAddr != "https://smsf:8009" {
		t.Errorf("defaults: nef=%q smsf=%q", cfg.NEFAddr, cfg.SMSFAddr)
	}
	t.Setenv("NEF_ADDR", "https://localhost:8011")
	t.Setenv("SMSF_ADDR", "https://localhost:8009")
	cfg, err = Load(writeConfig(t, "transport: sse\n"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.NEFAddr != "https://localhost:8011" || cfg.SMSFAddr != "https://localhost:8009" {
		t.Errorf("env: nef=%q smsf=%q", cfg.NEFAddr, cfg.SMSFAddr)
	}
}
