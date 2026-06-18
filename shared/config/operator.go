// Package operatorcfg provides shared operator-level configuration (PLMN and S-NSSAIs)
// read from a single canonical YAML file, eliminating duplication across NF configs.
//
// Precedence chain (lowest → highest):
//  1. NF hard-coded Go defaults
//  2. /etc/5gc/operator.yaml (this package)
//  3. /etc/5gc/config.yaml  (per-NF YAML — always wins)
//
// Usage in any NF Load() function:
//
//	if op, err := operatorcfg.LoadOperator(""); err != nil {
//	    return nil, fmt.Errorf("operator config: %w", err)
//	} else if op != nil {
//	    op.ApplyToPLMN(&cfg.PLMN.MCC, &cfg.PLMN.MNC)
//	}
package operatorcfg

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const defaultOperatorConfigPath = "/etc/5gc/operator.yaml"

// PLMN identifies the operator (MCC + MNC). Ref: TS 23.003 §12.1.
type PLMN struct {
	MCC string `yaml:"mcc"`
	MNC string `yaml:"mnc"`
}

// SNSSAIEntry is a single S-NSSAI in the operator slice list.
type SNSSAIEntry struct {
	SST int    `yaml:"sst"`
	SD  string `yaml:"sd"`
}

// DNNEntry defines operator-wide DNN → subnet configuration.
// Each DNN has an isolated UE IP pool and a dedicated N6 Docker network.
// Ref: TS 23.501 §5.6.5, TS 29.571 §5.4
type DNNEntry struct {
	Name        string `yaml:"name"`
	UEIPPool    string `yaml:"ue_ip_pool"`
	N6Network   string `yaml:"n6_network"`
	Description string `yaml:"description,omitempty"`
}

// OperatorConfig holds operator-wide configuration shared by all NFs.
type OperatorConfig struct {
	PLMN    PLMN          `yaml:"plmn"`
	SNSSAIs []SNSSAIEntry `yaml:"snssais"`
	DNNs    []DNNEntry    `yaml:"dnns"`
}

// LoadOperator reads the operator config from:
//  1. the explicit path argument (if non-empty)
//  2. the OPERATOR_CONFIG_PATH environment variable
//  3. /etc/5gc/operator.yaml (default)
//
// Returns (nil, nil) when the file does not exist — callers treat nil as
// "no operator config" and fall through to their own defaults.
func LoadOperator(path string) (*OperatorConfig, error) {
	if path == "" {
		path = os.Getenv("OPERATOR_CONFIG_PATH")
	}
	if path == "" {
		path = defaultOperatorConfigPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("operatorcfg: read %s: %w", path, err)
	}

	var op OperatorConfig
	if err := yaml.Unmarshal(data, &op); err != nil {
		return nil, fmt.Errorf("operatorcfg: parse YAML: %w", err)
	}
	return &op, nil
}

// ApplyToPLMN fills *mcc and *mnc from the operator config only when they are
// currently empty. Call this AFTER yaml.Unmarshal so the per-NF config wins.
func (op *OperatorConfig) ApplyToPLMN(mcc, mnc *string) {
	if op == nil {
		return
	}
	if *mcc == "" && op.PLMN.MCC != "" {
		*mcc = op.PLMN.MCC
	}
	if *mnc == "" && op.PLMN.MNC != "" {
		*mnc = op.PLMN.MNC
	}
}

// Slices returns the canonical operator slice list, or nil when the
// OperatorConfig was not loaded.
func (op *OperatorConfig) Slices() []SNSSAIEntry {
	if op == nil {
		return nil
	}
	return op.SNSSAIs
}

// DNNList returns the canonical operator DNN list, or nil when not loaded.
func (op *OperatorConfig) DNNList() []DNNEntry {
	if op == nil {
		return nil
	}
	return op.DNNs
}
