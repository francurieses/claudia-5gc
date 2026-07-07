// Package config loads and validates the MCP server runtime configuration.
// It mirrors the YAML schema in mcp/config/dev.yaml. Environment variables
// override selected fields so the same image works across compose profiles.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

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
	NRFAddr        string `yaml:"nrf_addr"`
	AMFAddr        string `yaml:"amf_addr"`
	PCFAddr        string `yaml:"pcf_addr"`
	SMFAddr        string `yaml:"smf_addr"`
	UDMAddr        string `yaml:"udm_addr"`
	JaegerAddr     string `yaml:"jaeger_addr"`
	PrometheusAddr string `yaml:"prometheus_addr"`
	// PortalAddr is mgmt-portal's plain-HTTP API, used by Group F to reach
	// UERANSIM containers via POST /api/v1/ueransim/nr-cli. MCP never talks to
	// Docker directly: it is reachable over SSE by external LLM clients, so
	// mounting the Docker socket into it would hand out root-equivalent host
	// access to whoever can drive a tool call. mgmt-portal already holds that
	// socket (read-only mount, internal network only) and exposes exec as a
	// narrow, validated HTTP endpoint.
	PortalAddr string `yaml:"portal_addr"`

	// Upstream TLS material for reaching the NRF SBI (which enforces mTLS).
	// Empty ⇒ H2C cleartext for dev. CAFile verifies the server; ClientCertFile
	// /ClientKeyFile authenticate this MCP server (TS 33.501 §13).
	CAFile         string `yaml:"ca_file"`
	ClientCertFile string `yaml:"client_cert_file"`
	ClientKeyFile  string `yaml:"client_key_file"`

	// UERANSIM configures Group F orchestration tools.
	UERANSIM UERANSIMConfig `yaml:"ueransim"`

	// Prometheus configures Group G metrics tools (overrides prometheus_addr timeout).
	Prometheus PrometheusConfig `yaml:"prometheus"`
}

// UERANSIMConfig holds Group F tool parameters.
type UERANSIMConfig struct {
	// ContainerName is the docker container running nr-ue (default: ueransim-ue).
	ContainerName string `yaml:"container_name"`
	// ExecTimeoutSec is the per-command HTTP timeout to mgmt-portal's nr-cli
	// proxy, in seconds (default: 25). Must exceed mgmt-portal's own internal
	// exec timeout (20s, tools/mgmt-portal/internal/api/ueransim.go) — otherwise
	// this client cancels the request context first, which propagates into
	// mgmt-portal's handler and kills its in-flight docker exec early.
	ExecTimeoutSec int `yaml:"exec_timeout_sec"`
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
// Empty token ⇒ authentication disabled (dev default).
type Auth struct {
	BearerToken string `yaml:"bearer_token"`
}

// Enabled reports whether Bearer authentication is required.
func (a Auth) Enabled() bool { return a.BearerToken != "" }

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
	if v := os.Getenv("JAEGER_ADDR"); v != "" {
		c.JaegerAddr = v
	}
	if v := os.Getenv("PROMETHEUS_ADDR"); v != "" {
		c.PrometheusAddr = v
	}
	if v := os.Getenv("PORTAL_ADDR"); v != "" {
		c.PortalAddr = v
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
	if c.JaegerAddr == "" {
		c.JaegerAddr = "http://jaeger:16686"
	}
	if c.PrometheusAddr == "" {
		c.PrometheusAddr = "http://prometheus:9090"
	}
	if c.PortalAddr == "" {
		c.PortalAddr = "http://mgmt-portal:8080"
	}
	if c.UERANSIM.ContainerName == "" {
		c.UERANSIM.ContainerName = "ueransim-ue"
	}
	if c.UERANSIM.ExecTimeoutSec <= 0 {
		c.UERANSIM.ExecTimeoutSec = 25
	}
	if c.Prometheus.QueryTimeoutSec <= 0 {
		c.Prometheus.QueryTimeoutSec = 5
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
