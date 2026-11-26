package roaming

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"
)

// PartnersFileEnv overrides the config key roaming.partners_file (SEPP-005).
const PartnersFileEnv = "ROAMING_PARTNERS_FILE"

// DefaultPartnersFile is the partners file path used when neither the env var nor
// roaming.partners_file is set (host: config/roaming/partners.yaml).
const DefaultPartnersFile = "/etc/5gc/roaming/partners.yaml"

// partnersDoc is the AMF-relevant slice of the shared partners file; the SEPP's
// "n32:" block and any other unknown key is tolerated (not parsed).
type partnersDoc struct {
	Partners []struct {
		PLMN    PLMN `yaml:"plmn"`
		HomeNFs *struct {
			AUSFAPIRoot string `yaml:"ausf_api_root"`
			UDMAPIRoot  string `yaml:"udm_api_root"`
			SMFAPIRoot  string `yaml:"smf_api_root"`
		} `yaml:"home_nfs"`
	} `yaml:"partners"`
}

// LoadPartners reads the partners file at path and returns the home PLMNs it
// defines (entries with home_nfs only; the others are the SEPP's business). A
// missing file is "no partners" (INFO, nil error). Invalid YAML, a malformed or
// duplicate PLMN, or a non-https/mismatching apiRoot is an error (fail closed).
// Ref: TS 29.500 §6.1.4.3; TS 23.003 §28.3.2.1
func LoadPartners(path string, log *slog.Logger) ([]HomePLMN, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		if log != nil {
			log.Info("roaming partners file absent: no partners", "nf", "AMF", "procedure", "RoamingPartners",
				"file", path, "spec_ref", "TS 29.500 §6.1.4.3")
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("amf: roaming: read partners file %s: %w", path, err)
	}
	var doc partnersDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("amf: roaming: partners file %s: %w", path, err)
	}
	seen := map[PLMN]bool{}
	var out []HomePLMN
	for i, p := range doc.Partners {
		if !digits(p.PLMN.MCC, 3) || !mncOK(p.PLMN.MNC) {
			return nil, fmt.Errorf("amf: roaming: partners[%d]: invalid plmn %s", i, p.PLMN)
		}
		if seen[p.PLMN] {
			return nil, fmt.Errorf("amf: roaming: partners[%d]: duplicate plmn %s", i, p.PLMN)
		}
		seen[p.PLMN] = true
		if p.HomeNFs == nil {
			continue
		}
		for _, f := range []struct{ name, v string }{{"ausf_api_root", p.HomeNFs.AUSFAPIRoot}, {"udm_api_root", p.HomeNFs.UDMAPIRoot}} {
			if err := validateAPIRoot(f.v, p.PLMN); err != nil {
				return nil, fmt.Errorf("amf: roaming: partners[%d].home_nfs.%s: %w", i, f.name, err)
			}
		}
		if p.HomeNFs.SMFAPIRoot != "" {
			if err := validateAPIRoot(p.HomeNFs.SMFAPIRoot, p.PLMN); err != nil {
				return nil, fmt.Errorf("amf: roaming: partners[%d].home_nfs.smf_api_root: %w", i, err)
			}
		}
		out = append(out, HomePLMN{PLMN: p.PLMN, AUSFAPIRoot: p.HomeNFs.AUSFAPIRoot, UDMAPIRoot: p.HomeNFs.UDMAPIRoot,
			SMFAPIRoot: p.HomeNFs.SMFAPIRoot})
	}
	return out, nil
}

// PartnersPath resolves the partners file path: env ROAMING_PARTNERS_FILE, else
// cfg.PartnersFile, else DefaultPartnersFile.
func (c Config) PartnersPath() string {
	if v := os.Getenv(PartnersFileEnv); v != "" {
		return v
	}
	if c.PartnersFile != "" {
		return c.PartnersFile
	}
	return DefaultPartnersFile
}

// MergePartners returns cfg with the file's home PLMNs merged in: a file entry
// overrides an inline home_plmns entry of the same PLMN, other inline entries are
// kept (inline first, in order).
func MergePartners(cfg Config, file []HomePLMN) Config {
	byPLMN := map[PLMN]HomePLMN{}
	for _, h := range file {
		byPLMN[h.PLMN] = h
	}
	merged := make([]HomePLMN, 0, len(cfg.HomePLMNs)+len(file))
	for _, h := range cfg.HomePLMNs {
		if f, ok := byPLMN[h.PLMN]; ok {
			merged = append(merged, f)
			delete(byPLMN, h.PLMN)
		} else {
			merged = append(merged, h)
		}
	}
	for _, h := range file {
		if _, ok := byPLMN[h.PLMN]; ok {
			merged = append(merged, h)
		}
	}
	out := cfg
	out.HomePLMNs = merged
	return out
}

// ResolveConfig loads the partners file (see PartnersPath) and merges it into
// cfg. With roaming disabled cfg is returned unchanged. Testable constructor:
// NewFromFile builds the Router straight from a file path.
func ResolveConfig(cfg Config, log *slog.Logger) (Config, error) {
	if !cfg.Enabled {
		return cfg, nil
	}
	file, err := LoadPartners(cfg.PartnersPath(), log)
	if err != nil {
		return cfg, err
	}
	return MergePartners(cfg, file), nil
}

// NewFromFile is New with the partners read from an explicit file path.
func NewFromFile(cfg Config, path, servingMCC, servingMNC string, log *slog.Logger) (*Router, error) {
	file, err := LoadPartners(path, log)
	if err != nil {
		return nil, err
	}
	return New(MergePartners(cfg, file), servingMCC, servingMNC)
}
