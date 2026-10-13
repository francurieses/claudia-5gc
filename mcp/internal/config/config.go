// Package config loads and validates the MCP server runtime configuration.
// It mirrors the YAML schema in mcp/config/dev.yaml. Environment variables
// override selected fields so the same image works across compose profiles.
package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// metricsHostRe is the accepted shape of metrics_host_override: a bare host name or IPv4.
var metricsHostRe = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)

// Transport selects which MCP transport(s) to run.
type Transport string

const (
	TransportStdio Transport = "stdio"
	TransportSSE   Transport = "sse"
	TransportBoth  Transport = "both"
)

// Config is the MCP server configuration.
type Config struct {
	// Transport: stdio | sse | both (default both).
	Transport Transport `yaml:"transport"`

	SSE  SSE  `yaml:"sse"`
	Auth Auth `yaml:"auth"`

	// Upstream service addresses consumed by Group B/C/D/H tools.
	NRFAddr string `yaml:"nrf_addr"`
	AMFAddr string `yaml:"amf_addr"`
	PCFAddr string `yaml:"pcf_addr"`
	SMFAddr string `yaml:"smf_addr"`
	UDMAddr string `yaml:"udm_addr"`
	// BSFAddr is the BSF Nbsf_Management SBI (mTLS), used by pcf_binding_list.
	BSFAddr string `yaml:"bsf_addr"`
	// NEFAddr is the NEF Nnef_AFsessionWithQoS SBI (mTLS), used by af_qos_session_*.
	NEFAddr string `yaml:"nef_addr"`
	// SMSFAddr is the SMSF internal MT-SMS trigger (mTLS), used by sms_send_mt.
	SMSFAddr       string `yaml:"smsf_addr"`
	JaegerAddr     string `yaml:"jaeger_addr"`
	PrometheusAddr string `yaml:"prometheus_addr"`
	// PortalAddr is mgmt-portal's plain-HTTP API, used by the status, control,
	// runtime-config and PCAP tools. MCP never talks to Docker directly: it is
	// reachable over SSE by external LLM clients, so mounting the Docker socket
	// into it would hand out root-equivalent host access to whoever can drive a
	// tool call. mgmt-portal already holds that socket (read-only mount, internal
	// network only) and exposes the few actions MCP needs as validated endpoints.
	PortalAddr string `yaml:"portal_addr"`

	// Upstream TLS material for reaching the NRF SBI (which enforces mTLS).
	// Empty ⇒ H2C cleartext for dev. CAFile verifies the server; ClientCertFile
	// /ClientKeyFile authenticate this MCP server (TS 33.501 §13).
	CAFile         string `yaml:"ca_file"`
	ClientCertFile string `yaml:"client_cert_file"`
	ClientKeyFile  string `yaml:"client_key_file"`

	// Prometheus configures Group G metrics tools (overrides prometheus_addr timeout).
	Prometheus PrometheusConfig `yaml:"prometheus"`

	// LokiAddr is the Loki query API used by log_query and procedure_timeline.
	LokiAddr string `yaml:"loki_addr"`

	// MetricsHostOverride replaces the host part of each NF metrics address that
	// Prometheus reports (smf:9105 becomes localhost:9105), keeping the port. Set it
	// when MCP runs on the host and cannot resolve Docker container names. Empty
	// (default) leaves the addresses unchanged.
	MetricsHostOverride string `yaml:"metrics_host_override"`

	// AccessMode caps the risk level the server exposes: read-only | operator | lab.
	AccessMode string `yaml:"access_mode"`
	// AllowServiceControl must be true before nf_service_control can run. It is
	// refused in every mode other than lab, even with an admin token.
	AllowServiceControl bool `yaml:"allow_service_control"`

	Guardrails Guardrails `yaml:"guardrails"`
}

// Guardrails bounds the side effects of tool calls.
type Guardrails struct {
	// MinIntervalMs is the minimum gap between two confirmed disruptive calls
	// across all tools (default 2000).
	MinIntervalMs int `yaml:"min_interval_ms"`
	// MaxResultBytes caps a single tool result; larger results return an error
	// asking the caller to narrow the query (default 262144).
	MaxResultBytes int `yaml:"max_result_bytes"`
	// AuditSize is the number of audit entries kept in memory (default 256).
	AuditSize int `yaml:"audit_size"`
}

// PrometheusConfig holds Group G tool parameters (supplements prometheus_addr).
type PrometheusConfig struct {
	// Addr overrides the top-level prometheus_addr for Group G tools if non-empty.
	Addr string `yaml:"addr"`
	// QueryTimeoutSec is the per-query HTTP timeout (default: 5).
	QueryTimeoutSec int `yaml:"query_timeout_sec"`
}

// SSE configures the HTTP Server-Sent-Events transport.
type SSE struct {
	ListenAddr string `yaml:"listen_addr"`
	TLS        TLS    `yaml:"tls"`
	// Debug enables the /mcp/sessions endpoint (dev only).
	Debug bool `yaml:"debug"`
}

// TLS holds the SSE listener certificate material. Empty cert/key ⇒ plain HTTP.
// A non-empty ca_file additionally enables mTLS (client cert required).
type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
}

// Enabled reports whether a TLS certificate is configured for the SSE listener.
func (t TLS) Enabled() bool { return t.CertFile != "" && t.KeyFile != "" }

// Auth configures optional Bearer-token authentication on the SSE transport.
// No token configured ⇒ authentication disabled (dev default; callers act as
// operator). bearer_token is the operator token; tokens map other tokens to a
// role. MCP_TOKEN_VIEWER / MCP_TOKEN_OPERATOR / MCP_TOKEN_ADMIN add entries.
type Auth struct {
	BearerToken string      `yaml:"bearer_token"`
	Tokens      []AuthToken `yaml:"tokens"`
}

// AuthToken binds a bearer token to a caller role (viewer | operator | admin).
type AuthToken struct {
	Token string `yaml:"token"`
	Role  string `yaml:"role"`
}

// Enabled reports whether Bearer authentication is required.
func (a Auth) Enabled() bool { return a.BearerToken != "" || len(a.Tokens) > 0 }

// Load reads YAML from path (defaults to /etc/5gc/config.yaml), applies env
// overrides, fills defaults, and validates.
func Load(path string) (*Config, error) {
	if path == "" {
		path = "/etc/5gc/config.yaml"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("mcp config: read %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("mcp config: parse yaml: %w", err)
	}
	c.applyEnv()
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("mcp config: validate: %w", err)
	}
	return &c, nil
}

func (c *Config) applyEnv() {
	if v := os.Getenv("MCP_TRANSPORT"); v != "" {
		c.Transport = Transport(strings.ToLower(v))
	}
	if v := os.Getenv("MCP_SSE_LISTEN_ADDR"); v != "" {
		c.SSE.ListenAddr = v
	}
	if v := os.Getenv("MCP_BEARER_TOKEN"); v != "" {
		c.Auth.BearerToken = v
	}
	if v := os.Getenv("NRF_ADDR"); v != "" {
		c.NRFAddr = v
	}
	if v := os.Getenv("AMF_ADDR"); v != "" {
		c.AMFAddr = v
	}
	if v := os.Getenv("PCF_ADDR"); v != "" {
		c.PCFAddr = v
	}
	if v := os.Getenv("SMF_ADDR"); v != "" {
		c.SMFAddr = v
	}
	if v := os.Getenv("UDM_ADDR"); v != "" {
		c.UDMAddr = v
	}
	if v := os.Getenv("BSF_ADDR"); v != "" {
		c.BSFAddr = v
	}
	if v := os.Getenv("NEF_ADDR"); v != "" {
		c.NEFAddr = v
	}
	if v := os.Getenv("SMSF_ADDR"); v != "" {
		c.SMSFAddr = v
	}
	if v := os.Getenv("JAEGER_ADDR"); v != "" {
		c.JaegerAddr = v
	}
	if v := os.Getenv("PROMETHEUS_ADDR"); v != "" {
		c.PrometheusAddr = v
	}
	if v := os.Getenv("PORTAL_ADDR"); v != "" {
		c.PortalAddr = v
	}
	if v := os.Getenv("LOKI_ADDR"); v != "" {
		c.LokiAddr = v
	}
	if v := os.Getenv("MCP_METRICS_HOST_OVERRIDE"); v != "" {
		c.MetricsHostOverride = v
	}
	if v := os.Getenv("MCP_ACCESS_MODE"); v != "" {
		c.AccessMode = strings.ToLower(v)
	}
	for _, t := range []struct{ env, role string }{
		{"MCP_TOKEN_VIEWER", "viewer"},
		{"MCP_TOKEN_OPERATOR", "operator"},
		{"MCP_TOKEN_ADMIN", "admin"},
	} {
		if v := os.Getenv(t.env); v != "" {
			c.Auth.Tokens = append(c.Auth.Tokens, AuthToken{Token: v, Role: t.role})
		}
	}
}

func (c *Config) applyDefaults() {
	if c.Transport == "" {
		c.Transport = TransportBoth
	}
	if c.SSE.ListenAddr == "" {
		c.SSE.ListenAddr = "0.0.0.0:9300"
	}
	if c.NRFAddr == "" {
		c.NRFAddr = "https://nrf:8000"
	}
	if c.AMFAddr == "" {
		c.AMFAddr = "http://amf:9002"
	}
	if c.PCFAddr == "" {
		c.PCFAddr = "https://pcf:8006"
	}
	if c.SMFAddr == "" {
		c.SMFAddr = "https://smf:8004"
	}
	if c.UDMAddr == "" {
		c.UDMAddr = "https://udm:8003"
	}
	if c.BSFAddr == "" {
		c.BSFAddr = "https://bsf:8010"
	}
	if c.NEFAddr == "" {
		c.NEFAddr = "https://nef:8011"
	}
	if c.SMSFAddr == "" {
		c.SMSFAddr = "https://smsf:8009"
	}
	if c.JaegerAddr == "" {
		c.JaegerAddr = "http://jaeger:16686"
	}
	if c.PrometheusAddr == "" {
		c.PrometheusAddr = "http://prometheus:9090"
	}
	if c.PortalAddr == "" {
		c.PortalAddr = "http://mgmt-portal:8080"
	}
	if c.Prometheus.QueryTimeoutSec <= 0 {
		c.Prometheus.QueryTimeoutSec = 5
	}
	if c.LokiAddr == "" {
		c.LokiAddr = "http://loki:3100"
	}
	if c.AccessMode == "" {
		c.AccessMode = "read-only"
	}
	if c.Guardrails.MinIntervalMs <= 0 {
		c.Guardrails.MinIntervalMs = 2000
	}
	if c.Guardrails.MaxResultBytes <= 0 {
		c.Guardrails.MaxResultBytes = 256 << 10
	}
	if c.Guardrails.AuditSize <= 0 {
		c.Guardrails.AuditSize = 256
	}
}

// PrometheusAddr returns the effective Prometheus address for Group G tools —
// Prometheus.Addr takes precedence over the top-level PrometheusAddr.
func (c *Config) EffectivePrometheusAddr() string {
	if c.Prometheus.Addr != "" {
		return c.Prometheus.Addr
	}
	return c.PrometheusAddr
}

func (c *Config) validate() error {
	switch c.Transport {
	case TransportStdio, TransportSSE, TransportBoth:
	default:
		return fmt.Errorf("transport must be stdio|sse|both, got %q", c.Transport)
	}
	if c.Transport != TransportStdio && c.SSE.ListenAddr == "" {
		return fmt.Errorf("sse.listen_addr is required when transport includes sse")
	}
	if c.SSE.TLS.CertFile != "" && c.SSE.TLS.KeyFile == "" {
		return fmt.Errorf("sse.tls.key_file required when cert_file is set")
	}
	switch c.AccessMode {
	case "read-only", "operator", "lab":
	default:
		return fmt.Errorf("access_mode must be read-only|operator|lab, got %q", c.AccessMode)
	}
	if c.MetricsHostOverride != "" && !metricsHostRe.MatchString(c.MetricsHostOverride) {
		return fmt.Errorf("metrics_host_override must be a host name or IP without scheme or port, got %q", c.MetricsHostOverride)
	}
	for i, t := range c.Auth.Tokens {
		if t.Token == "" {
			return fmt.Errorf("auth.tokens[%d]: token is empty", i)
		}
		switch t.Role {
		case "viewer", "operator", "admin":
		default:
			return fmt.Errorf("auth.tokens[%d]: role must be viewer|operator|admin, got %q", i, t.Role)
		}
	}
	return nil
}

// RunsStdio reports whether the stdio transport should start.
func (c *Config) RunsStdio() bool {
	return c.Transport == TransportStdio || c.Transport == TransportBoth
}

// RunsSSE reports whether the SSE transport should start.
func (c *Config) RunsSSE() bool {
	return c.Transport == TransportSSE || c.Transport == TransportBoth
}
