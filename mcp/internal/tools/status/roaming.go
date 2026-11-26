package status

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/mcp/internal/mcperr"
	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
	"github.com/francurieses/claudia-5gc/mcp/internal/tools/registry"
)

const (
	// roamingNotDeployedMsg is the D4 message of the roaming status design
	// (docs/procedures/RoamingStatus.md §5).
	roamingNotDeployedMsg = "no SEPP / roaming profile deployed: start it with docker compose --profile core --profile roaming up -d"
	// roamingUnknownMsg is the D5 message.
	roamingUnknownMsg = "roaming state unknown: portal and Prometheus unreachable"
	// roamingHRNote explains the home-routed inference (no HR-role field in the SMF view).
	roamingHRNote = "Inferred: every SMF session of a roaming UE (IMSI MCC+MNC not the local PLMN) is counted as home-routed. " +
		"This core has no local breakout for inbound roamers and the SMF management view has no home-routed role field. " +
		"Ref: TS 23.502 §4.3.2.2.2."
	roamingLocalPLMNUnknown = "local PLMN unknown"
	// imsiMinDigits / imsiMaxDigits bound the IMSI length (TS 23.003 §2.2: at most 15 digits;
	// at least MCC + 2-digit MNC + 1 digit).
	imsiMinDigits = 6
	imsiMaxDigits = 15
)

// The four SEPP series read from Prometheus (names: shared SEPP metrics).
const (
	roamQueryEstablished = `fivegc_sepp_n32c_context_established`
	roamQueryHandshake   = `sum by (role, peer_plmn, result) (fivegc_sepp_n32c_handshake_total)`
	roamQueryN32F        = `sum by (role, peer_plmn, direction, result) (fivegc_sepp_n32f_messages_total)`
	roamQueryTLSReject   = `sum by (role, reason) (fivegc_sepp_n32_tls_reject_total)`
)

var partnerPLMNRe = regexp.MustCompile(`^\d{3}-\d{2,3}$`)

// roamingStatusTool joins, in one read-only snapshot, the portal roaming view,
// the SEPP N32 Prometheus series, the AMF UE list and the SMF session list.
// Ref: TS 29.573 §5.2.2 (N32-c), §5.3.3 (N32-f), TS 33.501 §13.1.2, TS 23.501 §4.2.4.
type roamingStatusTool struct{ d Deps }

func (roamingStatusTool) Name() string        { return "roaming_status" }
func (roamingStatusTool) Risk() registry.Risk { return registry.ReadOnly }
func (roamingStatusTool) Description() string {
	return "Roaming snapshot: N32 link state, per roaming partner (PLMN, MCC-MNC) the N32 context and N32-c/N32-f counters on " +
		"the local SEPP and the partner test SEPP, N32 TLS rejects by reason, roaming UEs (AMF) and the home-routed " +
		"sessions of those UEs (SMF), plus per-source health. Sources are the portal, Prometheus, the AMF and the SMF; " +
		"a source that fails only marks its block unavailable. With no roaming deployed the result is deployed=false " +
		"with a hint. Optional partner_plmn (MCC-MNC, e.g. 001-002) filters partners and roamers. " +
		"Ref: TS 29.573 §5, TS 33.501 §13.1.2, TS 23.502 §4.3.2.2.2."
}
func (roamingStatusTool) InputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{
"partner_plmn":{"type":"string","pattern":"^\\d{3}-\\d{2,3}$","description":"Roaming partner PLMN as MCC-MNC, e.g. 001-002 (001-02 is the same partner)"}}}`)
}
func (roamingStatusTool) OutputSchema() json.RawMessage {
	return schema(`{"type":"object","properties":{"deployed":{"type":"boolean"},"message":{"type":"string"},` +
		`"local_plmn":{"type":"string"},"link":{"type":"object"},"partners":{"type":"array"},"tls_rejects":{"type":"object"},` +
		`"roaming_ues":{"type":"object"},"home_routed_sessions":{"type":"object"},"sources":{"type":"object"}}}`)
}

// ---- output types ---------------------------------------------------------

type roamLink struct {
	State       string `json:"state"`
	Reason      string `json:"reason,omitempty"`
	PartnerPLMN string `json:"partner_plmn,omitempty"`
}

type roamHandshakes struct {
	OK      int64 `json:"ok"`
	Reject  int64 `json:"reject"`
	Failure int64 `json:"failure"`
}

type roamN32F struct {
	OutOK   int64 `json:"out_ok"`
	InOK    int64 `json:"in_ok"`
	Reject  int64 `json:"reject"`
	Failure int64 `json:"failure"`
}

type roamSEPP struct {
	SEPP               string          `json:"sepp"`
	ContextState       string          `json:"context_state,omitempty"`
	ContextEstablished *bool           `json:"context_established,omitempty"`
	Handshakes         *roamHandshakes `json:"handshakes,omitempty"`
	N32F               *roamN32F       `json:"n32f,omitempty"`
}

type roamPartner struct {
	PLMN  string     `json:"plmn"`
	SEPPs []roamSEPP `json:"sepps"`
}

type roamUE struct {
	SUPI     string `json:"supi"`
	HomePLMN string `json:"home_plmn"`
	GMMState string `json:"gmm_state,omitempty"`
	CMState  string `json:"cm_state,omitempty"`
}

type roamUEs struct {
	Available bool     `json:"available"`
	Count     int      `json:"count"`
	UEs       []roamUE `json:"ues"`
	Error     string   `json:"error,omitempty"`
}

type roamSnssai struct {
	SST int    `json:"sst"`
	SD  string `json:"sd,omitempty"`
}

type roamSession struct {
	SUPI     string     `json:"supi"`
	HomePLMN string     `json:"home_plmn"`
	PSI      int        `json:"pdu_session_id"`
	DNN      string     `json:"dnn"`
	Snssai   roamSnssai `json:"snssai"`
	UEIP     string     `json:"ue_ip,omitempty"`
	State    string     `json:"state,omitempty"`
}

type roamSessions struct {
	Available bool          `json:"available"`
	Count     int           `json:"count"`
	Sessions  []roamSession `json:"sessions"`
	Note      string        `json:"note"`
	Error     string        `json:"error,omitempty"`
}

type roamResult struct {
	Deployed   bool                        `json:"deployed"`
	Message    string                      `json:"message,omitempty"`
	LocalPLMN  string                      `json:"local_plmn"`
	Link       roamLink                    `json:"link"`
	Partners   []roamPartner               `json:"partners"`
	TLSRejects map[string]map[string]int64 `json:"tls_rejects,omitempty"`
	RoamingUEs *roamUEs                    `json:"roaming_ues,omitempty"`
	HomeRouted *roamSessions               `json:"home_routed_sessions,omitempty"`
	Sources    map[string]string           `json:"sources"`
}

// ---- source views ---------------------------------------------------------

type portalView struct {
	Deployed bool `json:"deployed"`
	Link     struct {
		State       string `json:"state"`
		Reason      string `json:"reason"`
		LocalPLMN   string `json:"local_plmn"`
		PartnerPLMN string `json:"partner_plmn"`
	} `json:"link"`
	SEPPs []struct {
		Name  string `json:"name"`
		Error string `json:"error"`
		N32   *struct {
			LocalPLMN string `json:"local_plmn"`
			Partners  []struct {
				PLMN  string `json:"plmn"`
				State string `json:"state"`
			} `json:"partners"`
		} `json:"n32"`
	} `json:"sepps"`
}

// promData holds the SEPP series, keyed role -> normalised peer PLMN.
type promData struct {
	established map[string]map[string]bool
	handshakes  map[string]map[string]*roamHandshakes
	n32f        map[string]map[string]*roamN32F
	tlsRejects  map[string]map[string]int64
	any         bool
}

type amfUE struct {
	SUPI     string `json:"supi"`
	GMMState string `json:"gmm_state"`
	CMState  string `json:"cm_state"`
}

// ---- PLMN helpers ---------------------------------------------------------

// normPLMN converts "MCC/MNC" or "MCC-MNC" (2- or 3-digit MNC) to "MCC-MNC" with the
// MNC padded to 3 digits, the SEPP PlmnId.Key() form. ok is false for other/unknown.
func normPLMN(s string) (string, bool) {
	s = strings.ReplaceAll(strings.TrimSpace(s), "/", "-")
	if !partnerPLMNRe.MatchString(s) {
		return "", false
	}
	if len(s) == 6 {
		return s[:4] + "0" + s[4:], true
	}
	return s, true
}

// imsiDigits returns the digits of an imsi- SUPI; ok is false for other SUPI formats.
func imsiDigits(supi string) (string, bool) {
	d, found := strings.CutPrefix(supi, "imsi-")
	// IMSI is 6..15 digits (MCC + MNC + MSIN), TS 23.003 §2.2.
	if !found || len(d) < imsiMinDigits || len(d) > imsiMaxDigits {
		return "", false
	}
	for _, c := range d {
		if c < '0' || c > '9' {
			return "", false
		}
	}
	return d, true
}

// imsiIsLocal reports whether the IMSI starts with the local MCC+MNC (3-digit MNC, or
// its 2-digit form when the 3-digit MNC has a leading zero). TS 23.003 §2.2.
func imsiIsLocal(d, local string) bool {
	mcc, mnc := local[:3], local[4:]
	if strings.HasPrefix(d, mcc+mnc) {
		return true
	}
	return mnc[0] == '0' && strings.HasPrefix(d, mcc+mnc[1:])
}

// imsiHome matches the IMSI against the partner PLMNs, 3-digit MNC first, then 2-digit.
func imsiHome(d string, partners map[string]bool) string {
	if p := d[:3] + "-" + d[3:6]; partners[p] {
		return p
	}
	if p := d[:3] + "-0" + d[3:5]; partners[p] {
		return p
	}
	return "unknown"
}

// classify returns (home PLMN, roaming). Non-IMSI SUPIs are never roaming.
func classify(supi, local string, partners map[string]bool) (string, bool) {
	d, ok := imsiDigits(supi)
	if !ok || imsiIsLocal(d, local) {
		return "", false
	}
	return imsiHome(d, partners), true
}

// ---- Invoke ---------------------------------------------------------------

func (t roamingStatusTool) Invoke(ctx context.Context, in json.RawMessage) (any, error) {
	start := time.Now()
	var a struct {
		PartnerPLMN string `json:"partner_plmn"`
	}
	if len(in) > 0 && string(in) != "null" {
		// Unknown top-level args are refused with -32602 (internal/tools/CLAUDE.md).
		dec := json.NewDecoder(bytes.NewReader(in))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&a); err != nil {
			return nil, mcperr.Newf(mcperr.CodeInvalidParams, nil, "roaming_status args: %v", err)
		}
	}
	filter := ""
	if a.PartnerPLMN != "" {
		if !partnerPLMNRe.MatchString(a.PartnerPLMN) {
			return nil, mcperr.Newf(mcperr.CodeInvalidParams, map[string]any{"partner_plmn": a.PartnerPLMN},
				"partner_plmn must match ^\\d{3}-\\d{2,3}$ (MCC-MNC), got %q", a.PartnerPLMN)
		}
		filter, _ = normPLMN(a.PartnerPLMN)
	}

	var (
		wg                                 sync.WaitGroup
		portal                             *portalView
		prom                               *promData
		ues                                []amfUE
		sessions                           []smfSessionRow
		portalErr, promErr, amfErr, smfErr error
	)
	bounded := func(f func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, sourceTimeout)
			defer cancel()
			f(c)
		}()
	}
	bounded(func(c context.Context) { portal, portalErr = t.readPortal(c) })
	bounded(func(c context.Context) { prom, promErr = t.readProm(c) })
	bounded(func(c context.Context) { ues, amfErr = t.readAMF(c) })
	bounded(func(c context.Context) { sessions, smfErr = t.readSMF(c) })
	wg.Wait()

	res := roamResult{Partners: []roamPartner{}, Sources: map[string]string{
		"portal": srcStatus(portalErr), "prometheus": srcStatus(promErr), "amf": srcStatus(amfErr), "smf": srcStatus(smfErr),
	}}
	if portal != nil {
		res.Link = roamLink{State: portal.Link.State, Reason: portal.Link.Reason}
		res.Link.PartnerPLMN, _ = normPLMN(portal.Link.PartnerPLMN)
	}

	// A local SEPP the portal reports unreachable (error, no N32 view) with no
	// fivegc_sepp series is not deployed either (D4).
	localDown := false
	if portal != nil {
		for _, s := range portal.SEPPs {
			if s.Name == "sepp" && s.Error != "" && s.N32 == nil {
				localDown = true
			}
		}
	}
	portalDeployed := portal != nil && portal.Deployed && portal.Link.State != "NOT_DEPLOYED" && !localDown
	promHas := prom != nil && prom.any
	switch {
	case portalErr != nil && promErr != nil:
		res.Message = roamingUnknownMsg
	case !promHas && !portalDeployed:
		res.Message = roamingNotDeployedMsg
	default:
		res.Deployed = true
	}
	if !res.Deployed {
		t.log(ctx, res, start)
		return res, nil
	}

	// Local PLMN: link first, else the local SEPP's own PLMN. A malformed value is kept
	// out but its cause is recorded for the roaming_ues / home_routed_sessions error.
	localCause := ""
	if portal != nil {
		if p, ok := normPLMN(portal.Link.LocalPLMN); ok {
			res.LocalPLMN = p
		} else if portal.Link.LocalPLMN != "" {
			localCause = fmt.Sprintf("portal local_plmn %q malformed", portal.Link.LocalPLMN)
		}
		if res.LocalPLMN == "" {
			for _, s := range portal.SEPPs {
				if s.Name == "hsepp" || s.N32 == nil {
					continue
				}
				if p, ok := normPLMN(s.N32.LocalPLMN); ok {
					res.LocalPLMN = p
					break
				} else if s.N32.LocalPLMN != "" && localCause == "" {
					localCause = fmt.Sprintf("portal sepp %q local_plmn %q malformed", s.Name, s.N32.LocalPLMN)
				}
			}
		}
	}

	known := t.buildPartners(&res, portal, prom, filter)
	if prom != nil {
		res.TLSRejects = prom.tlsRejects
	}

	// Roaming UEs and home-routed sessions.
	if res.LocalPLMN == "" {
		msg := roamingLocalPLMNUnknown
		if localCause != "" {
			msg += ": " + localCause
		}
		res.RoamingUEs = &roamUEs{UEs: []roamUE{}, Error: msg}
		res.HomeRouted = &roamSessions{Sessions: []roamSession{}, Note: roamingHRNote, Error: msg}
	} else {
		res.RoamingUEs = &roamUEs{UEs: []roamUE{}}
		if amfErr != nil {
			res.RoamingUEs.Error = amfErr.Error()
		} else {
			res.RoamingUEs.Available = true
			for _, u := range ues {
				if home, roaming := classify(u.SUPI, res.LocalPLMN, known); roaming && (filter == "" || filter == home) {
					res.RoamingUEs.UEs = append(res.RoamingUEs.UEs, roamUE{u.SUPI, home, u.GMMState, u.CMState})
				}
			}
			sort.Slice(res.RoamingUEs.UEs, func(i, j int) bool { return res.RoamingUEs.UEs[i].SUPI < res.RoamingUEs.UEs[j].SUPI })
			res.RoamingUEs.Count = len(res.RoamingUEs.UEs)
		}
		res.HomeRouted = &roamSessions{Sessions: []roamSession{}, Note: roamingHRNote}
		if smfErr != nil {
			res.HomeRouted.Error = smfErr.Error()
		} else {
			res.HomeRouted.Available = true
			for _, s := range sessions {
				if home, roaming := classify(s.SUPI, res.LocalPLMN, known); roaming && (filter == "" || filter == home) {
					res.HomeRouted.Sessions = append(res.HomeRouted.Sessions, roamSession{
						SUPI: s.SUPI, HomePLMN: home, PSI: s.PSI, DNN: s.DNN,
						Snssai: roamSnssai{SST: s.SNssai.SST, SD: s.SNssai.SD}, UEIP: s.UEIP, State: s.SessionState,
					})
				}
			}
			sort.Slice(res.HomeRouted.Sessions, func(i, j int) bool {
				a, b := res.HomeRouted.Sessions[i], res.HomeRouted.Sessions[j]
				if a.SUPI != b.SUPI {
					return a.SUPI < b.SUPI
				}
				return a.PSI < b.PSI
			})
			res.HomeRouted.Count = len(res.HomeRouted.Sessions)
		}
	}
	t.log(ctx, res, start)
	return res, nil
}

func srcStatus(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

func (t roamingStatusTool) log(ctx context.Context, r roamResult, start time.Time) {
	slog.InfoContext(ctx, "roaming status read", "nf", "MCP", "procedure", "RoamingStatus",
		"tool_name", "roaming_status", "interface", "Portal/Prometheus/Namf/Nsmf", "direction", "OUT",
		"spec_ref", "TS 29.573 §5", "deployed", r.Deployed, "partners", len(r.Partners), "sources", r.Sources,
		"latency_ms", time.Since(start).Milliseconds())
}

// buildPartners fills res.Partners (after the partner filter) and returns the set of
// every known partner PLMN, used to classify roamers.
func (t roamingStatusTool) buildPartners(res *roamResult, portal *portalView, prom *promData, filter string) map[string]bool {
	known := map[string]bool{}
	state := map[string]string{}   // local SEPP: partner -> portal state
	hsState := map[string]string{} // hSEPP: its partner PLMN -> portal state
	hsLocal := ""
	if portal != nil {
		for _, s := range portal.SEPPs {
			if s.N32 == nil {
				continue
			}
			if s.Name == "hsepp" {
				hsLocal, _ = normPLMN(s.N32.LocalPLMN)
				for _, p := range s.N32.Partners {
					if n, ok := normPLMN(p.PLMN); ok {
						hsState[n] = p.State
					}
				}
				continue
			}
			for _, p := range s.N32.Partners {
				if n, ok := normPLMN(p.PLMN); ok {
					known[n] = true
					state[n] = p.State
				}
			}
		}
	}
	if prom != nil {
		for p := range prom.established["sepp"] {
			known[p] = true
		}
		for p := range prom.handshakes["sepp"] {
			known[p] = true
		}
		for p := range prom.n32f["sepp"] {
			known[p] = true
		}
	}
	order := make([]string, 0, len(known))
	for p := range known {
		order = append(order, p)
	}
	sort.Strings(order)

	// hSEPP attachment (docs/procedures/RoamingStatus.md): to the partner whose PLMN is
	// the hSEPP's own (portal hsepp local_plmn); with no such information only when there
	// is exactly one partner AND exactly one hSEPP peer. Everything is by sorted slices,
	// never by map iteration order.
	hsPeerSet := map[string]bool{}
	if prom != nil {
		for k := range peersOf(prom, "hsepp") {
			hsPeerSet[k] = true
		}
	}
	for k := range hsState {
		hsPeerSet[k] = true
	}
	hsPeers := make([]string, 0, len(hsPeerSet))
	for k := range hsPeerSet {
		hsPeers = append(hsPeers, k)
	}
	sort.Strings(hsPeers)
	hsTarget := ""
	if hsLocal != "" && known[hsLocal] {
		hsTarget = hsLocal
	} else if len(order) == 1 && len(hsPeers) == 1 {
		hsTarget = order[0]
	}
	// hsPeer is the hSEPP's peer that is the local PLMN; with the local PLMN unknown
	// only a single peer is unambiguous.
	hsPeer := ""
	if res.LocalPLMN != "" {
		if hsPeerSet[res.LocalPLMN] {
			hsPeer = res.LocalPLMN
		}
	} else if len(hsPeers) == 1 {
		hsPeer = hsPeers[0]
	}

	for _, p := range order {
		if filter != "" && filter != p {
			continue
		}
		e := roamSEPP{SEPP: "sepp", ContextState: state[p]}
		if prom != nil {
			fillProm(&e, prom, "sepp", p)
		}
		out := roamPartner{PLMN: p, SEPPs: []roamSEPP{e}}
		if p == hsTarget && hsPeer != "" {
			h := roamSEPP{SEPP: "hsepp", ContextState: hsState[hsPeer]}
			if prom != nil {
				fillProm(&h, prom, "hsepp", hsPeer)
			}
			if h.ContextState != "" || h.ContextEstablished != nil || h.Handshakes != nil || h.N32F != nil {
				out.SEPPs = append(out.SEPPs, h)
			}
		}
		res.Partners = append(res.Partners, out)
	}
	return known
}

func peersOf(p *promData, role string) map[string]bool {
	m := map[string]bool{}
	for k := range p.established[role] {
		m[k] = true
	}
	for k := range p.handshakes[role] {
		m[k] = true
	}
	for k := range p.n32f[role] {
		m[k] = true
	}
	return m
}

func fillProm(e *roamSEPP, p *promData, role, peer string) {
	if v, ok := p.established[role][peer]; ok {
		e.ContextEstablished = &v
	}
	if h := p.handshakes[role][peer]; h != nil {
		e.Handshakes = h
	}
	if f := p.n32f[role][peer]; f != nil {
		e.N32F = f
	}
}

// ---- readers --------------------------------------------------------------

func (t roamingStatusTool) readPortal(ctx context.Context) (*portalView, error) {
	if t.d.Portal == nil {
		return nil, fmt.Errorf("portal not configured")
	}
	raw, err := t.d.Portal.Get(ctx, "/roaming/status", nil)
	if err != nil {
		return nil, err
	}
	var v portalView
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("decode portal roaming status: %w", err)
	}
	return &v, nil
}

func (t roamingStatusTool) readAMF(ctx context.Context) ([]amfUE, error) {
	if t.d.AMF == nil {
		return nil, fmt.Errorf("amf not configured")
	}
	raw, err := t.d.AMF.ListContexts(ctx)
	if err != nil {
		return nil, err
	}
	var out []amfUE
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode AMF list: %w", err)
	}
	return out, nil
}

func (t roamingStatusTool) readSMF(ctx context.Context) ([]smfSessionRow, error) {
	return readSMFSessions(ctx, t.d.SMF)
}

// readProm runs the four SEPP queries concurrently. Any failure marks Prometheus
// unavailable as a whole (no partial counters); every failure is reported.
func (t roamingStatusTool) readProm(ctx context.Context) (*promData, error) {
	if t.d.Prom == nil {
		return nil, fmt.Errorf("prometheus not configured")
	}
	queries := []string{roamQueryEstablished, roamQueryHandshake, roamQueryN32F, roamQueryTLSReject}
	results := make([]*promclient.QueryResult, len(queries))
	errs := make([]error, len(queries))
	var wg sync.WaitGroup
	for i, q := range queries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = t.d.Prom.Query(ctx, q, time.Time{})
		}()
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	p := &promData{
		established: map[string]map[string]bool{},
		handshakes:  map[string]map[string]*roamHandshakes{},
		n32f:        map[string]map[string]*roamN32F{},
		tlsRejects:  map[string]map[string]int64{},
	}
	// sample returns the value of a sample; ok is false for a non-finite or negative
	// value (NaN, +-Inf, unparsable), which is unknown, not 0: such a sample is skipped.
	sample := func(s promclient.VectorSample) (float64, bool) {
		f := s.Float64()
		if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
			return 0, false
		}
		return f, true
	}
	count := func(f float64) int64 { return int64(f + 0.5) }
	// Counter note: a partner with at least one finite series whose result label is
	// absent keeps 0 for it. That is not "missing as 0": the counter child is created at
	// its first increment, so no series means it was never incremented.
	for _, s := range results[0].Data.Result {
		role, peer := s.Metric["role"], s.Metric["peer_plmn"]
		f, ok := sample(s)
		if !ok {
			continue
		}
		p.any = p.any || role != ""
		if n, ok := normPLMN(peer); ok && role != "" {
			if p.established[role] == nil {
				p.established[role] = map[string]bool{}
			}
			p.established[role][n] = p.established[role][n] || f == 1
		}
	}
	for _, s := range results[1].Data.Result {
		role := s.Metric["role"]
		f, ok := sample(s)
		if !ok {
			continue
		}
		p.any = p.any || role != ""
		n, ok := normPLMN(s.Metric["peer_plmn"])
		if !ok || role == "" {
			continue
		}
		if p.handshakes[role] == nil {
			p.handshakes[role] = map[string]*roamHandshakes{}
		}
		h := p.handshakes[role][n]
		if h == nil {
			h = &roamHandshakes{}
			p.handshakes[role][n] = h
		}
		switch strings.ToLower(s.Metric["result"]) {
		case "ok":
			h.OK += count(f)
		case "reject":
			h.Reject += count(f)
		case "failure":
			h.Failure += count(f)
		}
	}
	for _, s := range results[2].Data.Result {
		role := s.Metric["role"]
		f, ok := sample(s)
		if !ok {
			continue
		}
		p.any = p.any || role != ""
		n, ok := normPLMN(s.Metric["peer_plmn"])
		if !ok || role == "" {
			continue
		}
		if p.n32f[role] == nil {
			p.n32f[role] = map[string]*roamN32F{}
		}
		x := p.n32f[role][n]
		if x == nil {
			x = &roamN32F{}
			p.n32f[role][n] = x
		}
		dir := strings.ToLower(s.Metric["direction"])
		switch strings.ToLower(s.Metric["result"]) {
		case "ok":
			switch dir {
			case "out":
				x.OutOK += count(f)
			case "in":
				x.InOK += count(f)
			}
		case "reject":
			x.Reject += count(f)
		case "failure":
			x.Failure += count(f)
		}
	}
	for _, s := range results[3].Data.Result {
		role, reason := s.Metric["role"], s.Metric["reason"]
		f, ok := sample(s)
		if !ok {
			continue
		}
		p.any = p.any || role != ""
		if role == "" || reason == "" {
			continue
		}
		if p.tlsRejects[role] == nil {
			p.tlsRejects[role] = map[string]int64{}
		}
		p.tlsRejects[role][reason] += count(f)
	}
	return p, nil
}
