package api

// partners.go — roaming partners editor (SEPP-005).
//
//	GET /api/v1/roaming/partners   parsed partners file + effective list from the SEPP admin API
//	PUT /api/v1/roaming/partners   validate, write atomically, restart sepp and amf
//
// The file is shared by the SEPP, the AMF and the portal (env
// ROAMING_PARTNERS_FILE, default /etc/5gc/roaming/partners.yaml). The SEPP and
// AMF read it at startup only, so applying a change = restart of both.
// Ref: TS 23.003 §28.5.2 (SEPP FQDN), TS 33.501 §13.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultPartnersFile is the in-container path of the roaming partners file.
	DefaultPartnersFile = "/etc/5gc/roaming/partners.yaml"
	// DefaultSEPPAdminBase is the SEPP admin (metrics port) base URL on obs-net.
	DefaultSEPPAdminBase = "http://sepp:9115"
	// partnersProbeBudget bounds the effective-list request to the SEPP.
	partnersProbeBudget = 3 * time.Second
	// partnersRestartBudget bounds the restart of each container.
	partnersRestartBudget = 60 * time.Second
)

// partnersMu serialises PUTs: file write and container restarts happen under it.
var partnersMu sync.Mutex

// partnerCAFile is the only CA path the portal accepts for a partner: the
// operator drops the partner CA there on the host (pki/n32/peers/<mcc>-<mnc>/ca.crt).
func partnerCAFile(p PartnerPLMN) string {
	return "/etc/5gc/pki/n32/peers/" + p.MCC + "-" + p.MNC + "/ca.crt"
}

func zeroPad3(mnc string) string {
	for len(mnc) < 3 {
		mnc = "0" + mnc
	}
	return mnc
}

// partnerDomainSuffix is the FQDN suffix every partner host must carry
// (TS 23.003 §28.3.2.1, §28.5.2).
func partnerDomainSuffix(p PartnerPLMN) string {
	return ".5gc.mnc" + zeroPad3(p.MNC) + ".mcc" + p.MCC + ".3gppnetwork.org"
}

func hostInPartnerDomain(host string, p PartnerPLMN) bool {
	return strings.HasSuffix(strings.ToLower(host), partnerDomainSuffix(p)) &&
		len(host) > len(partnerDomainSuffix(p))
}

// partnersRestartTargets are restarted after a save (they read the file at startup).
var partnersRestartTargets = []string{"sepp", "amf"}

var (
	mccRe = regexp.MustCompile(`^[0-9]{3}$`)
	mncRe = regexp.MustCompile(`^[0-9]{2,3}$`)
)

// PartnerPLMN is the PLMN identity of a partner.
type PartnerPLMN struct {
	MCC string `yaml:"mcc" json:"mcc"`
	MNC string `yaml:"mnc" json:"mnc"`
}

// PartnerN32 is the SEPP-side configuration of a partner.
type PartnerN32 struct {
	CAFile   string `yaml:"ca_file" json:"ca_file"`
	SEPPFQDN string `yaml:"sepp_fqdn,omitempty" json:"sepp_fqdn,omitempty"`
	Address  string `yaml:"address,omitempty" json:"address,omitempty"`
}

// PartnerHomeNFs is the AMF-side configuration of a partner.
type PartnerHomeNFs struct {
	AUSFAPIRoot string `yaml:"ausf_api_root,omitempty" json:"ausf_api_root,omitempty"`
	UDMAPIRoot  string `yaml:"udm_api_root,omitempty" json:"udm_api_root,omitempty"`
	SMFAPIRoot  string `yaml:"smf_api_root,omitempty" json:"smf_api_root,omitempty"`
}

// RoamingPartner is one entry of partners.yaml.
type RoamingPartner struct {
	PLMN    PartnerPLMN     `yaml:"plmn" json:"plmn"`
	N32     PartnerN32      `yaml:"n32" json:"n32"`
	HomeNFs *PartnerHomeNFs `yaml:"home_nfs,omitempty" json:"home_nfs,omitempty"`
}

type partnersFile struct {
	Partners []RoamingPartner `yaml:"partners"`
}

// ValidatePartners checks the partner list against the shared file schema.
func ValidatePartners(ps []RoamingPartner) error {
	seen := map[string]bool{}
	for i, p := range ps {
		at := fmt.Sprintf("partners[%d]", i)
		if !mccRe.MatchString(p.PLMN.MCC) {
			return fmt.Errorf("%s: mcc must be 3 digits", at)
		}
		if !mncRe.MatchString(p.PLMN.MNC) {
			return fmt.Errorf("%s: mnc must be 2 or 3 digits", at)
		}
		key := p.PLMN.MCC + "-" + p.PLMN.MNC
		if seen[key] {
			return fmt.Errorf("%s: duplicate PLMN %s", at, key)
		}
		seen[key] = true
		if p.N32.CAFile != partnerCAFile(p.PLMN) {
			return fmt.Errorf("%s: n32.ca_file must be %s", at, partnerCAFile(p.PLMN))
		}
		if a := p.N32.Address; a != "" {
			if !validHostPort(a) {
				return fmt.Errorf("%s: n32.address must be host:port", at)
			}
		}
		if f := p.N32.SEPPFQDN; f != "" && !hostInPartnerDomain(f, p.PLMN) {
			return fmt.Errorf("%s: n32.sepp_fqdn must end with %s", at, partnerDomainSuffix(p.PLMN))
		}
		if h := p.HomeNFs; h != nil {
			for name, v := range map[string]string{"ausf_api_root": h.AUSFAPIRoot, "udm_api_root": h.UDMAPIRoot, "smf_api_root": h.SMFAPIRoot} {
				if v == "" {
					continue
				}
				u, err := url.Parse(v)
				if err != nil || u.Scheme != "https" || u.Hostname() == "" || (u.Path != "" && u.Path != "/") {
					return fmt.Errorf("%s: home_nfs.%s must be an https URL without path", at, name)
				}
				if !hostInPartnerDomain(u.Hostname(), p.PLMN) {
					return fmt.Errorf("%s: home_nfs.%s host must end with %s", at, name, partnerDomainSuffix(p.PLMN))
				}
			}
		}
	}
	return nil
}

func validHostPort(s string) bool {
	u, err := url.Parse("//" + s)
	if err != nil || u.Hostname() == "" || u.Port() == "" || u.Path != "" || u.User != nil {
		return false
	}
	return true
}

// ReadPartnersFile parses the partners file; a missing file is an empty list.
func ReadPartnersFile(path string) ([]RoamingPartner, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return []RoamingPartner{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("partners: read %s: %w", path, err)
	}
	var f partnersFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("partners: parse %s: %w", path, err)
	}
	if f.Partners == nil {
		f.Partners = []RoamingPartner{}
	}
	return f.Partners, nil
}

// WritePartnersFile writes the file atomically (temp file in the same
// directory + rename, mode 0644).
func WritePartnersFile(path string, ps []RoamingPartner) error {
	if ps == nil {
		ps = []RoamingPartner{}
	}
	b, err := yaml.Marshal(partnersFile{Partners: ps})
	if err != nil {
		return fmt.Errorf("partners: marshal: %w", err)
	}
	hdr := []byte("# Roaming partners — managed by the portal (Roaming page); read by sepp and amf at startup.\n")
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".partners-*.tmp")
	if err != nil {
		return fmt.Errorf("partners: temp file: %w", err)
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // no-op after a successful rename
	if _, err := tmp.Write(append(hdr, b...)); err != nil {
		tmp.Close() //nolint:errcheck
		return fmt.Errorf("partners: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close() //nolint:errcheck
		return fmt.Errorf("partners: fsync temp: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close() //nolint:errcheck
		return fmt.Errorf("partners: chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("partners: close temp: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("partners: rename: %w", err)
	}
	return nil
}

func (d Deps) partnersFile() string {
	if d.PartnersFile != "" {
		return d.PartnersFile
	}
	return DefaultPartnersFile
}

func (d Deps) seppAdminBase() string {
	if d.SEPPAdminBase != "" {
		return strings.TrimRight(d.SEPPAdminBase, "/")
	}
	return DefaultSEPPAdminBase
}

// lifecycle returns the container lifecycle used for restarts (nil = unavailable).
func (d Deps) lifecycle() serviceLifecycle {
	if d.Lifecycle != nil {
		return d.Lifecycle
	}
	if d.Docker != nil {
		return d.Docker
	}
	return nil
}

// effectivePartners fetches the SEPP's effective partner list as raw JSON.
func (d Deps) effectivePartners(ctx context.Context) (json.RawMessage, string) {
	ctx, cancel := context.WithTimeout(ctx, partnersProbeBudget)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.seppAdminBase()+"/admin/v1/n32/partners", nil)
	if err != nil {
		return nil, err.Error()
	}
	resp, err := d.httpClient().Do(req)
	if err != nil {
		return nil, "SEPP admin unreachable: " + err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Sprintf("SEPP admin answered %d (SEPP image older than SEPP-005?)", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || !json.Valid(b) {
		return nil, "SEPP admin returned an invalid body"
	}
	return b, ""
}

type partnersResponse struct {
	File            []RoamingPartner `json:"file"`
	Path            string           `json:"path"`
	Effective       json.RawMessage  `json:"effective"`
	EffectiveReason string           `json:"effective_reason,omitempty"`
}

func (d Deps) handleGetPartners(w http.ResponseWriter, r *http.Request) {
	ps, err := ReadPartnersFile(d.partnersFile())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	eff, reason := d.effectivePartners(r.Context())
	if eff == nil {
		eff = json.RawMessage("null")
	}
	writeJSON(w, http.StatusOK, partnersResponse{File: ps, Path: d.partnersFile(), Effective: eff, EffectiveReason: reason})
}

type partnersPutRequest struct {
	Partners []RoamingPartner `json:"partners"`
}

// sameOriginJSON is the CSRF mitigation for the (unauthenticated) mutating
// route: a present Origin must match Host and the body must be application/json
// (a simple cross-site form post cannot set that).
func sameOriginJSON(r *http.Request) string {
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || u.Host != r.Host {
			return "cross-origin request refused"
		}
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		return "Content-Type must be application/json"
	}
	return ""
}

func (d Deps) handlePutPartners(w http.ResponseWriter, r *http.Request) {
	if msg := sameOriginJSON(r); msg != "" {
		writeError(w, http.StatusForbidden, msg)
		return
	}
	var req partnersPutRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	for i := range req.Partners {
		if req.Partners[i].N32.CAFile == "" {
			req.Partners[i].N32.CAFile = partnerCAFile(req.Partners[i].PLMN)
		}
	}
	if err := ValidatePartners(req.Partners); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	dc := d.lifecycle()
	if dc == nil {
		writeError(w, http.StatusServiceUnavailable, "docker unavailable")
		return
	}
	partnersMu.Lock()
	defer partnersMu.Unlock()
	if err := WritePartnersFile(d.partnersFile(), req.Partners); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	results := map[string]string{}
	failed := false
	for _, name := range partnersRestartTargets {
		ctx, cancel := context.WithTimeout(r.Context(), partnersRestartBudget)
		_, _, err := startOrRestart(ctx, dc, name, true)
		cancel()
		if err != nil {
			results[name] = "error: " + err.Error()
			failed = true
			continue
		}
		results[name] = "ok"
	}
	slog.Info("roaming partners saved", "path", d.partnersFile(), "count", len(req.Partners), "restart", results)
	status := http.StatusOK
	body := map[string]any{"saved": true, "partners": req.Partners, "restart": results}
	if failed {
		status = http.StatusBadGateway
		body["error"] = "partners saved but restarting a container failed"
	}
	writeJSON(w, status, body)
}
