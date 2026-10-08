// Package config loads UPF configuration from YAML.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/francurieses/claudia-5gc/nf/upf/internal/qos"
	operatorcfg "github.com/francurieses/claudia-5gc/shared/config"
)

// DNNConfig holds the per-DNN N6 TUN configuration for the UPF.
// Each DNN gets an isolated TUN interface so UE subnets never overlap.
// Ref: TS 23.501 §5.6.5, TS 29.244 §6.3.3.14 (Network Instance)
type DNNConfig struct {
	Name      string `yaml:"name"`
	UEIPPool  string `yaml:"ue_ip_pool"` // CIDR for UE addresses (e.g., "10.60.0.0/24")
	TunName   string `yaml:"tun_name"`   // TUN device name (e.g., "upfgtp0")
	TunAddr   string `yaml:"tun_addr"`   // CIDR assigned to TUN (e.g., "10.60.0.254/24")
	GatewayIP string `yaml:"gateway_ip"` // N6 bridge gateway for internet egress

	// UEIPv6Prefix is the delegated IPv6 base prefix for this DNN (e.g. a
	// /56 mirroring the SMF's per-DNN IPv6 pool), anchoring which per-DNN
	// user plane a session's Router Advertisement belongs to and guarding
	// that the DNN is IPv6-enabled. The advertiser primarily uses the /64
	// that arrived in the PFCP UE IP Address IE (TS 29.244 §8.2.62); empty
	// means the DNN has no IPv6 capability. Ref: TS 23.501 §5.8.2.2.
	UEIPv6Prefix string `yaml:"ue_ipv6_prefix"`
}

// Config holds UPF runtime configuration.
type Config struct {
	NFInstanceID string `yaml:"nf_instance_id"`
	PLMN         struct {
		MCC string `yaml:"mcc"`
		MNC string `yaml:"mnc"`
	} `yaml:"plmn"`
	N3 struct {
		Address string `yaml:"address"` // GTP-U listener address (e.g., 0.0.0.0:2152)
		IP      string `yaml:"ip"`      // UPF IP for N3 transport layer (e.g., 172.30.3.100)
		// SocketBufferBytes sets SO_RCVBUF/SO_SNDBUF of the GTP-U UDP socket
		// (0 = kernel default). Larger buffers absorb bursts instead of
		// dropping them (visible as Udp RcvbufErrors in /proc/net/snmp).
		SocketBufferBytes int `yaml:"socket_buffer_bytes"`
	} `yaml:"n3"`
	N4 struct {
		Address string `yaml:"address"` // PFCP listener address (e.g., 0.0.0.0:8805)
	} `yaml:"n4"`
	Metrics struct {
		Address string `yaml:"address"` // Prometheus metrics listener (e.g., 0.0.0.0:9107)
	} `yaml:"metrics"`
	// DNNs defines per-DNN TUN interfaces for N6 forwarding.
	// Adding a new DNN: append here and add the matching n6-<name>-net in docker-compose.yml.
	DNNs []DNNConfig `yaml:"dnns"`
	// UEIPPool and N6 are legacy single-DNN fields kept for backward compatibility.
	// They are superseded by DNNs when DNNs is non-empty.
	UEIPPool string `yaml:"ue_ip_pool"`
	N6       struct {
		GatewayIP string `yaml:"gateway_ip"`
		TunName   string `yaml:"tun_name"`
		TunAddr   string `yaml:"tun_addr"`
		// L4ChecksumRepair enables recomputing a wrong TCP/UDP checksum on
		// downlink packets read from the N6 TUN before GTP-U encapsulation
		// (UPF-003, RFC 1071). nil = default ON.
		L4ChecksumRepair *bool `yaml:"l4_checksum_repair"`
		// TunMTU sets the N6 TUN MTU (0 = kernel default 1500). 1456 =
		// 1500 - 44 (outer IPv4 20 + UDP 8 + GTP-U 8 + NG-U extension 8),
		// so a full-size inner packet is never IP-fragmented on N3.
		// Ref: TS 29.281 §5.1, TS 23.501 §5.6.10.4 [VERIFY clause].
		TunMTU int `yaml:"tun_mtu"`
		// TunTxQueueLen sets the N6 TUN txqueuelen (0 = kernel default).
		TunTxQueueLen int `yaml:"tun_txqueuelen"`
		// TCPMSSClamp installs TCPMSS --clamp-mss-to-pmtu on SYN segments
		// crossing the TUN so TCP sessions negotiate an MSS that fits the TUN MTU.
		TCPMSSClamp bool `yaml:"tcp_mss_clamp"`
	} `yaml:"n6"`
	// QoS configures MBR / Session-AMBR enforcement in the GTP-U datapath
	// (UPF-005, docs/procedures/AmbrEnforcement.md).
	QoS struct {
		// MBREnforcement polices traffic above the QER MBR and the
		// Session-AMBR. nil = default ON; false restores line-rate forwarding
		// (Gate Status CLOSED is still enforced). Ref: TS 23.501 §5.7.1.8.
		MBREnforcement *bool `yaml:"mbr_enforcement"`
		// BurstMs is the token-bucket depth in milliseconds of traffic at the
		// MBR (0 = default 100), clamped to [1, 1000]. A 4500-octet floor
		// always applies. Ref: TS 29.244 §5.4.4.
		BurstMs int `yaml:"burst_ms"`
	} `yaml:"qos"`
}

// QoSMBREnforcement reports whether MBR / Session-AMBR policing is enabled
// (UPF-005). It defaults to true when qos.mbr_enforcement is unset.
func (c *Config) QoSMBREnforcement() bool {
	if c.QoS.MBREnforcement == nil {
		return true
	}
	return *c.QoS.MBREnforcement
}

// QoSBurstMs returns the effective qos.burst_ms: 100 when unset or zero,
// otherwise clamped to [1, 1000].
func (c *Config) QoSBurstMs() int {
	return qos.ClampBurstMs(c.QoS.BurstMs)
}

// N6L4ChecksumRepair reports whether the N6 downlink L4 checksum repair
// (UPF-003) is enabled. It defaults to true when n6.l4_checksum_repair is unset.
func (c *Config) N6L4ChecksumRepair() bool {
	if c.N6.L4ChecksumRepair == nil {
		return true
	}
	return *c.N6.L4ChecksumRepair
}

// Load reads configuration from file or environment.
func Load() (*Config, error) {
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "/etc/5gc/config.yaml"
	}

	cfg := &Config{
		NFInstanceID: "00000000-0000-4007-8000-000000000001",
		UEIPPool:     "10.60.0.0/24",
	}

	// Set defaults
	cfg.N3.Address = "0.0.0.0:2152"
	cfg.N3.IP = "172.30.3.100"
	cfg.N4.Address = "0.0.0.0:8805"
	cfg.Metrics.Address = "0.0.0.0:9107"
	cfg.PLMN.MCC = "001"
	cfg.PLMN.MNC = "01"
	cfg.N6.GatewayIP = "172.30.6.1"
	cfg.N6.TunName = "upfgtp0"
	cfg.N6.TunAddr = "10.60.0.254/24"

	// Layer operator PLMN + DNN registry between Go defaults and per-NF YAML.
	if op, err := operatorcfg.LoadOperator(""); err != nil {
		return nil, fmt.Errorf("config: operator config: %w", err)
	} else if op != nil {
		op.ApplyToPLMN(&cfg.PLMN.MCC, &cfg.PLMN.MNC)
		// Operator DNNs pre-populate the UPF DNN list; per-NF YAML can override.
		// The N6 TUN fields (tun_name/tun_addr/gateway_ip) must still be set in
		// the per-NF YAML since they are deployment-specific.
		if dnnList := op.DNNList(); len(dnnList) > 0 && len(cfg.DNNs) == 0 {
			for i, d := range dnnList {
				cfg.DNNs = append(cfg.DNNs, DNNConfig{
					Name:     d.Name,
					UEIPPool: d.UEIPPool,
					// Derive sensible TUN defaults: upfgtpN, last-octet .254
					TunName: fmt.Sprintf("upfgtp%d", i),
				})
			}
		}
	}

	data, err := os.ReadFile(cfgPath)
	if err == nil {
		// File exists, parse it
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("config: parse YAML: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("config: read file: %w", err)
	}

	// Fall back to legacy single-DNN config when DNNs is still empty after YAML.
	if len(cfg.DNNs) == 0 {
		cfg.DNNs = []DNNConfig{{
			Name:      "internet",
			UEIPPool:  cfg.UEIPPool,
			TunName:   cfg.N6.TunName,
			TunAddr:   cfg.N6.TunAddr,
			GatewayIP: cfg.N6.GatewayIP,
		}}
	}

	return cfg, nil
}
