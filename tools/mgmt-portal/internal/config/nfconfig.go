// Package config reads and writes NF dev.yaml configuration files.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// SNSSAI represents a network slice identifier.
type SNSSAI struct {
	SST int    `yaml:"sst" json:"sst"`
	SD  string `yaml:"sd" json:"sd"`
}

// nfSliceConfig is the minimal YAML structure we care about for slices.
type nfSliceConfig struct {
	SNSSAIs       []SNSSAI `yaml:"snssais"`
	AllowedSlices []SNSSAI `yaml:"allowed_slices"` // NSSF uses this key
}

// ---- DNN types ------------------------------------------------------------

// OperatorDNN is a DNN entry as stored in operator.yaml.
type OperatorDNN struct {
	Name        string `yaml:"name" json:"name"`
	UEIPPool    string `yaml:"ue_ip_pool" json:"ue_ip_pool"`
	N6Network   string `yaml:"n6_network,omitempty" json:"n6_network,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// SMFDNNEntry is a DNN entry as stored in smf/config/dev.yaml.
type SMFDNNEntry struct {
	Name     string `yaml:"name"`
	UEIPPool string `yaml:"ue_ip_pool"`
}

// UPFDNNEntry is a DNN entry as stored in upf/config/dev.yaml.
type UPFDNNEntry struct {
	Name      string `yaml:"name"`
	UEIPPool  string `yaml:"ue_ip_pool"`
	TunName   string `yaml:"tun_name"`
	TunAddr   string `yaml:"tun_addr"`
	GatewayIP string `yaml:"gateway_ip"`
}

// DNNInfo is the merged view of a DNN across all config sources, used by the portal API.
type DNNInfo struct {
	Name        string `json:"name"`
	UEIPPool    string `json:"ue_ip_pool"`
	N6Network   string `json:"n6_network,omitempty"`
	Description string `json:"description,omitempty"`
	TunName     string `json:"tun_name,omitempty"`
	TunAddr     string `json:"tun_addr,omitempty"`
	GatewayIP   string `json:"gateway_ip,omitempty"`
	DockerNet   string `json:"docker_network,omitempty"`
}

// Manager reads and writes slice and DNN configuration across NF config files.
type Manager struct {
	configsPath  string // mounted path, e.g. /app/nf-configs
	operatorPath string // path to operator.yaml, e.g. /etc/5gc/operator.yaml
}

// New returns a Manager for the given NF configs root directory.
func New(configsPath string) *Manager {
	opPath := os.Getenv("OPERATOR_CONFIG_PATH")
	if opPath == "" {
		opPath = "/etc/5gc/operator.yaml"
	}
	return &Manager{configsPath: configsPath, operatorPath: opPath}
}

// configPath returns the path to a specific NF dev.yaml.
func (m *Manager) configPath(nf string) string {
	return filepath.Join(m.configsPath, nf, "config", "dev.yaml")
}

// ---- Slice methods --------------------------------------------------------

// ReadSlices reads the snssais list from a NF config file.
// Falls back to operator.yaml when the NF config has no slice list.
func (m *Manager) ReadSlices(nf string) ([]SNSSAI, error) {
	data, err := os.ReadFile(m.configPath(nf))
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", nf, err)
	}

	var cfg nfSliceConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", nf, err)
	}

	var slices []SNSSAI
	if nf == "nssf" {
		slices = cfg.AllowedSlices
	} else {
		slices = cfg.SNSSAIs
	}

	// NF config has no slices — fall back to shared operator.yaml.
	if len(slices) == 0 {
		return m.readOperatorSlices()
	}
	return slices, nil
}

// readOperatorSlices reads the canonical slice list from operator.yaml.
func (m *Manager) readOperatorSlices() ([]SNSSAI, error) {
	data, err := os.ReadFile(m.operatorPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []SNSSAI{}, nil
		}
		return nil, fmt.Errorf("config: read operator config: %w", err)
	}
	var cfg struct {
		SNSSAIs []SNSSAI `yaml:"snssais"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse operator config: %w", err)
	}
	if cfg.SNSSAIs == nil {
		return []SNSSAI{}, nil
	}
	return cfg.SNSSAIs, nil
}

// WriteSlices updates the snssais list in a NF config file, preserving all other fields.
func (m *Manager) WriteSlices(nf string, slices []SNSSAI) error {
	path := m.configPath(nf)
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: read %s: %w", nf, err)
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("config: parse %s: %w", nf, err)
	}

	snssais := make([]map[string]interface{}, len(slices))
	for i, s := range slices {
		snssais[i] = map[string]interface{}{"sst": s.SST, "sd": s.SD}
	}

	key := "snssais"
	if nf == "nssf" {
		key = "allowed_slices"
	}
	raw[key] = snssais

	out, err := yaml.Marshal(raw)
	if err != nil {
		return fmt.Errorf("config: marshal %s: %w", nf, err)
	}
	if err := os.WriteFile(path, out, 0644); err != nil {
		return fmt.Errorf("config: write %s: %w", nf, err)
	}
	return nil
}

// GetAllSlices returns the effective slice list shown in the portal Slices page.
// AMF is the source of truth; falls back to operator.yaml when AMF config has none.
func (m *Manager) GetAllSlices() ([]SNSSAI, error) {
	return m.ReadSlices("amf")
}

// ---- DNN methods ----------------------------------------------------------

// readOperatorFull loads the full operator.yaml as a raw map to preserve unknown fields.
func (m *Manager) readOperatorFull() (map[string]interface{}, error) {
	data, err := os.ReadFile(m.operatorPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]interface{}{}, nil
		}
		return nil, fmt.Errorf("config: read operator.yaml: %w", err)
	}
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("config: parse operator.yaml: %w", err)
	}
	if raw == nil {
		raw = map[string]interface{}{}
	}
	return raw, nil
}

// writeOperatorFull serialises a raw map back to operator.yaml.
func (m *Manager) writeOperatorFull(raw map[string]interface{}) error {
	out, err := yaml.Marshal(raw)
	if err != nil {
		return fmt.Errorf("config: marshal operator.yaml: %w", err)
	}
	return os.WriteFile(m.operatorPath, out, 0644)
}

// readOperatorDNNs returns the DNN list from operator.yaml.
func (m *Manager) readOperatorDNNs() ([]OperatorDNN, error) {
	data, err := os.ReadFile(m.operatorPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("config: read operator.yaml: %w", err)
	}
	var cfg struct {
		DNNs []OperatorDNN `yaml:"dnns"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse operator.yaml: %w", err)
	}
	return cfg.DNNs, nil
}

// writeOperatorDNNs persists the DNN list to operator.yaml, preserving other fields.
func (m *Manager) writeOperatorDNNs(dnns []OperatorDNN) error {
	raw, err := m.readOperatorFull()
	if err != nil {
		return err
	}
	items := make([]map[string]interface{}, 0, len(dnns))
	for _, d := range dnns {
		item := map[string]interface{}{"name": d.Name, "ue_ip_pool": d.UEIPPool}
		if d.N6Network != "" {
			item["n6_network"] = d.N6Network
		}
		if d.Description != "" {
			item["description"] = d.Description
		}
		items = append(items, item)
	}
	raw["dnns"] = items
	return m.writeOperatorFull(raw)
}

// ReadUPFDNNs returns the DNN list from the UPF config file.
func (m *Manager) ReadUPFDNNs() ([]UPFDNNEntry, error) {
	data, err := os.ReadFile(m.configPath("upf"))
	if err != nil {
		return nil, fmt.Errorf("config: read upf: %w", err)
	}
	var cfg struct {
		DNNs []UPFDNNEntry `yaml:"dnns"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse upf: %w", err)
	}
	return cfg.DNNs, nil
}

// WriteUPFDNNs persists the DNN list to the UPF config, preserving other fields.
func (m *Manager) WriteUPFDNNs(dnns []UPFDNNEntry) error {
	path := m.configPath("upf")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: read upf: %w", err)
	}
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("config: parse upf: %w", err)
	}
	if raw == nil {
		raw = map[string]interface{}{}
	}
	items := make([]map[string]interface{}, 0, len(dnns))
	for _, d := range dnns {
		items = append(items, map[string]interface{}{
			"name":       d.Name,
			"ue_ip_pool": d.UEIPPool,
			"tun_name":   d.TunName,
			"tun_addr":   d.TunAddr,
			"gateway_ip": d.GatewayIP,
		})
	}
	raw["dnns"] = items
	out, err := yaml.Marshal(raw)
	if err != nil {
		return fmt.Errorf("config: marshal upf: %w", err)
	}
	return os.WriteFile(path, out, 0644)
}

// ReadSMFDNNs returns the DNN list from the SMF config file.
func (m *Manager) ReadSMFDNNs() ([]SMFDNNEntry, error) {
	data, err := os.ReadFile(m.configPath("smf"))
	if err != nil {
		return nil, fmt.Errorf("config: read smf: %w", err)
	}
	var cfg struct {
		DNNs []SMFDNNEntry `yaml:"dnns"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse smf: %w", err)
	}
	return cfg.DNNs, nil
}

// WriteSMFDNNs persists the DNN list to the SMF config, preserving other fields.
func (m *Manager) WriteSMFDNNs(dnns []SMFDNNEntry) error {
	path := m.configPath("smf")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: read smf: %w", err)
	}
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("config: parse smf: %w", err)
	}
	if raw == nil {
		raw = map[string]interface{}{}
	}
	items := make([]map[string]interface{}, 0, len(dnns))
	for _, d := range dnns {
		items = append(items, map[string]interface{}{
			"name":       d.Name,
			"ue_ip_pool": d.UEIPPool,
		})
	}
	raw["dnns"] = items
	out, err := yaml.Marshal(raw)
	if err != nil {
		return fmt.Errorf("config: marshal smf: %w", err)
	}
	return os.WriteFile(path, out, 0644)
}

// GetAllDNNs returns the merged DNN view combining operator.yaml and UPF config.
func (m *Manager) GetAllDNNs() ([]DNNInfo, error) {
	opDNNs, err := m.readOperatorDNNs()
	if err != nil {
		return nil, err
	}
	upfDNNs, _ := m.ReadUPFDNNs() // degrade gracefully if UPF config unavailable

	upfByName := make(map[string]UPFDNNEntry, len(upfDNNs))
	for _, u := range upfDNNs {
		upfByName[u.Name] = u
	}

	result := make([]DNNInfo, 0, len(opDNNs))
	for _, od := range opDNNs {
		info := DNNInfo{
			Name:        od.Name,
			UEIPPool:    od.UEIPPool,
			N6Network:   od.N6Network,
			Description: od.Description,
			DockerNet:   dockerNetName(od.Name),
		}
		if u, ok := upfByName[od.Name]; ok {
			info.TunName = u.TunName
			info.TunAddr = u.TunAddr
			info.GatewayIP = u.GatewayIP
		}
		result = append(result, info)
	}
	return result, nil
}

// SuggestNextDNN computes the next available UE IP pool, N6 network, and TUN index
// based on the currently configured DNNs.
func (m *Manager) SuggestNextDNN() (uePool, n6Net string, tunIdx int, err error) {
	existing, err := m.GetAllDNNs()
	if err != nil {
		return "", "", 0, err
	}
	tunIdx = len(existing)

	// UE pool: 10.<x>.0.0/24 where x starts at 60 (octets[1]).
	usedUESecond := map[int]bool{}
	for _, d := range existing {
		parts := strings.SplitN(d.UEIPPool, "/", 2)
		if len(parts) < 1 {
			continue
		}
		octets := strings.Split(parts[0], ".")
		if len(octets) == 4 {
			n, _ := strconv.Atoi(octets[1])
			usedUESecond[n] = true
		}
	}
	for i := 60; i < 256; i++ {
		if !usedUESecond[i] {
			uePool = fmt.Sprintf("10.%d.0.0/24", i)
			break
		}
	}

	// N6 network: 172.30.<x>.0/24 where x starts at 6 (octets[2]).
	usedN6Third := map[int]bool{}
	for _, d := range existing {
		if d.N6Network == "" {
			continue
		}
		parts := strings.SplitN(d.N6Network, "/", 2)
		if len(parts) < 1 {
			continue
		}
		octets := strings.Split(parts[0], ".")
		if len(octets) == 4 {
			n, _ := strconv.Atoi(octets[2])
			usedN6Third[n] = true
		}
	}
	for i := 6; i < 256; i++ {
		if !usedN6Third[i] {
			n6Net = fmt.Sprintf("172.30.%d.0/24", i)
			break
		}
	}
	return uePool, n6Net, tunIdx, nil
}

// AddDNN appends a new DNN to operator.yaml, SMF, and UPF config files.
// d.TunName, d.TunAddr, and d.GatewayIP are optional; they are derived from
// d.UEIPPool and d.N6Network when empty.
func (m *Manager) AddDNN(d DNNInfo, tunIdx int) error {
	tunName := d.TunName
	if tunName == "" {
		tunName = fmt.Sprintf("upfgtp%d", tunIdx)
	}
	tunAddr := d.TunAddr
	if tunAddr == "" {
		tunAddr = tunAddrFromPool(d.UEIPPool)
	}
	gwIP := d.GatewayIP
	if gwIP == "" {
		gwIP = gatewayFromN6Net(d.N6Network)
	}

	// operator.yaml
	opDNNs, err := m.readOperatorDNNs()
	if err != nil {
		return err
	}
	opDNNs = append(opDNNs, OperatorDNN{
		Name:        d.Name,
		UEIPPool:    d.UEIPPool,
		N6Network:   d.N6Network,
		Description: d.Description,
	})
	if err := m.writeOperatorDNNs(opDNNs); err != nil {
		return fmt.Errorf("config: write operator.yaml: %w", err)
	}

	// SMF
	smfDNNs, err := m.ReadSMFDNNs()
	if err != nil {
		return err
	}
	smfDNNs = append(smfDNNs, SMFDNNEntry{Name: d.Name, UEIPPool: d.UEIPPool})
	if err := m.WriteSMFDNNs(smfDNNs); err != nil {
		return fmt.Errorf("config: write smf: %w", err)
	}

	// UPF
	upfDNNs, err := m.ReadUPFDNNs()
	if err != nil {
		return err
	}
	upfDNNs = append(upfDNNs, UPFDNNEntry{
		Name:      d.Name,
		UEIPPool:  d.UEIPPool,
		TunName:   tunName,
		TunAddr:   tunAddr,
		GatewayIP: gwIP,
	})
	return m.WriteUPFDNNs(upfDNNs)
}

// DeleteDNN removes a DNN from operator.yaml, SMF, and UPF config files.
func (m *Manager) DeleteDNN(name string) error {
	// operator.yaml
	opDNNs, err := m.readOperatorDNNs()
	if err != nil {
		return err
	}
	newOp := opDNNs[:0]
	for _, d := range opDNNs {
		if d.Name != name {
			newOp = append(newOp, d)
		}
	}
	if err := m.writeOperatorDNNs(newOp); err != nil {
		return fmt.Errorf("config: write operator.yaml: %w", err)
	}

	// SMF
	smfDNNs, err := m.ReadSMFDNNs()
	if err != nil {
		return err
	}
	newSMF := smfDNNs[:0]
	for _, d := range smfDNNs {
		if d.Name != name {
			newSMF = append(newSMF, d)
		}
	}
	if err := m.WriteSMFDNNs(newSMF); err != nil {
		return fmt.Errorf("config: write smf: %w", err)
	}

	// UPF
	upfDNNs, err := m.ReadUPFDNNs()
	if err != nil {
		return err
	}
	newUPF := upfDNNs[:0]
	for _, d := range upfDNNs {
		if d.Name != name {
			newUPF = append(newUPF, d)
		}
	}
	return m.WriteUPFDNNs(newUPF)
}

// UpdateDNNDescription updates the description of a DNN in operator.yaml only.
// No NF restart is required for a description-only change.
func (m *Manager) UpdateDNNDescription(name, description string) error {
	opDNNs, err := m.readOperatorDNNs()
	if err != nil {
		return err
	}
	found := false
	for i := range opDNNs {
		if opDNNs[i].Name == name {
			opDNNs[i].Description = description
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("config: DNN %q not found", name)
	}
	return m.writeOperatorDNNs(opDNNs)
}

// ---- Helpers --------------------------------------------------------------

// dockerNetName returns the Docker network name for a DNN.
// internet → "5gc-n6", others → "5gc-n6-<name>".
func dockerNetName(dnnName string) string {
	if dnnName == "internet" {
		return "5gc-n6"
	}
	return "5gc-n6-" + dnnName
}

// tunAddrFromPool derives the UPF TUN address from the UE IP pool CIDR.
// "10.60.0.0/24" → "10.60.0.254/24"
func tunAddrFromPool(ueIPPool string) string {
	parts := strings.SplitN(ueIPPool, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	octets := strings.Split(parts[0], ".")
	if len(octets) != 4 {
		return ""
	}
	octets[3] = "254"
	return strings.Join(octets, ".") + "/" + parts[1]
}

// gatewayFromN6Net derives the Docker bridge gateway from an N6 network CIDR.
// "172.30.6.0/24" → "172.30.6.1"
func gatewayFromN6Net(n6Network string) string {
	parts := strings.SplitN(n6Network, "/", 2)
	if len(parts) < 1 {
		return ""
	}
	octets := strings.Split(parts[0], ".")
	if len(octets) != 4 {
		return ""
	}
	octets[3] = "1"
	return strings.Join(octets, ".")
}
