package config

import (
	"log/slog"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestN6L4ChecksumRepair(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want bool
	}{
		{"unset defaults on", "nf_instance_id: x\n", true},
		{"n6 without knob defaults on", "n6:\n  tun_name: upfgtp0\n", true},
		{"explicit true", "n6:\n  l4_checksum_repair: true\n", true},
		{"explicit false", "n6:\n  l4_checksum_repair: false\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var c Config
			if err := yaml.Unmarshal([]byte(tc.yaml), &c); err != nil {
				t.Fatal(err)
			}
			if got := c.N6L4ChecksumRepair(); got != tc.want {
				t.Fatalf("N6L4ChecksumRepair = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestN6LegacyFieldsStillParse(t *testing.T) {
	var c Config
	y := "n6:\n  gateway_ip: 1.2.3.4\n  tun_name: t0\n  tun_addr: 10.0.0.1/24\n  l4_checksum_repair: false\n"
	if err := yaml.Unmarshal([]byte(y), &c); err != nil {
		t.Fatal(err)
	}
	if c.N6.GatewayIP != "1.2.3.4" || c.N6.TunName != "t0" || c.N6.TunAddr != "10.0.0.1/24" {
		t.Fatalf("legacy n6 fields broken: %+v", c.N6)
	}
}

func TestLogLevelFromEnv(t *testing.T) {
	cases := map[string]slog.Level{
		"":        slog.LevelInfo,
		"info":    slog.LevelInfo,
		"DEBUG":   slog.LevelDebug,
		" warn ":  slog.LevelWarn,
		"error":   slog.LevelError,
		"garbage": slog.LevelInfo,
	}
	for in, want := range cases {
		t.Setenv("LOG_LEVEL", in)
		if got := LogLevelFromEnv(); got != want {
			t.Errorf("LOG_LEVEL=%q: got %v want %v", in, got, want)
		}
	}
}

// TestDatapathDefaults: the tuning knobs default to the pre-tuning behaviour
// (kernel defaults, no MSS clamp) and parse when set.
func TestDatapathDefaults(t *testing.T) {
	var c Config
	if c.N3.SocketBufferBytes != 0 || c.N6.TunMTU != 0 || c.N6.TunTxQueueLen != 0 || c.N6.TCPMSSClamp {
		t.Fatalf("zero value is not the legacy behaviour: %+v", c)
	}
	const y = "n3:\n  socket_buffer_bytes: 8388608\nn6:\n  tun_mtu: 1456\n  tun_txqueuelen: 5000\n  tcp_mss_clamp: true\n"
	if err := yaml.Unmarshal([]byte(y), &c); err != nil {
		t.Fatal(err)
	}
	if c.N3.SocketBufferBytes != 8388608 || c.N6.TunMTU != 1456 || c.N6.TunTxQueueLen != 5000 || !c.N6.TCPMSSClamp {
		t.Fatalf("parsed %+v", c)
	}
}

// TestQoSKnobs: qos.mbr_enforcement defaults ON, qos.burst_ms defaults to 100 and
// is clamped to [1, 1000] (UPF-005).
func TestQoSKnobs(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		enforce bool
		burst   int
	}{
		{"unset", "nf_instance_id: x\n", true, 100},
		{"empty block", "qos: {}\n", true, 100},
		{"explicit off", "qos:\n  mbr_enforcement: false\n  burst_ms: 20\n", false, 20},
		{"explicit on", "qos:\n  mbr_enforcement: true\n  burst_ms: 250\n", true, 250},
		{"burst clamped low", "qos:\n  burst_ms: -3\n", true, 1},
		{"burst clamped high", "qos:\n  burst_ms: 99999\n", true, 1000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var c Config
			if err := yaml.Unmarshal([]byte(tc.yaml), &c); err != nil {
				t.Fatal(err)
			}
			if got := c.QoSMBREnforcement(); got != tc.enforce {
				t.Errorf("QoSMBREnforcement = %v, want %v", got, tc.enforce)
			}
			if got := c.QoSBurstMs(); got != tc.burst {
				t.Errorf("QoSBurstMs = %d, want %d", got, tc.burst)
			}
		})
	}
}
