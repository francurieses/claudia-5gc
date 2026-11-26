// Package roaming implements the local-core AMF side of roaming over N32
// (ROAM-001): classifying a UE as roaming from its SUCI/SUPI home network
// identifier, selecting the home AUSF/UDM apiRoot, and carrying the per-UE
// route that the Nausf/Nudm clients turn into "request to the local SEPP with
// 3gpp-Sbi-Target-apiRoot".
//
// The package is a leaf (no AMF imports) so the UE context, the registration
// procedure and the SBI clients can all use it. A nil *Router or a disabled
// config is "feature off": every UE is non-roaming and no route exists, so the
// non-roaming wire bytes are untouched.
//
// Ref: TS 23.502 §4.2.2.2.2; TS 23.501 §6.3.4; TS 33.501 §6.1.3.2;
// TS 29.500 §6.1.4.3.
package roaming

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
)

// TargetAPIRootHeader is the HTTP header carrying the home NF apiRoot on a
// request sent to the SEPP in the target-apiRoot header model.
// Ref: TS 29.500 §6.1.4.3 (3gpp-Sbi-Target-apiRoot)
const TargetAPIRootHeader = "3gpp-Sbi-Target-apiRoot"

// OriginatingNetworkIDHeader carries the PLMN ID of the source PLMN on a request
// sent towards a different PLMN; the value follows the TS 29.500 §5.2.3.2.15
// ABNF `3DIGIT "-" 2*3DIGIT` (MCC-MNC, e.g. "001-01"). An NF service consumer
// originating a request towards another PLMN shall insert it (Table 5.2.3.2.1-1);
// the receiving SEPP checks it against the sender's PLMN (TS 33.501 §5.9.3.5).
// Ref: TS 29.500 §5.2.3.2.15; TS 33.501 §5.9.3.5
const OriginatingNetworkIDHeader = "3gpp-Sbi-Originating-Network-Id"

// MaxRememberedRoutes bounds the per-SUPI route map (entries are also dropped on
// UE context removal and UECM deregistration); a full map refuses new entries.
const MaxRememberedRoutes = 100000

// ErrHomePLMNNotConfigured: the UE's home PLMN differs from the serving PLMN
// and has no roaming.home_plmns[] entry. The registration is rejected with
// 5GMM cause #11 and no SBI request is made (procedure doc §5).
var ErrHomePLMNNotConfigured = errors.New("roaming: home PLMN not configured")

// PLMN is an MCC/MNC pair; the MNC keeps its digit count (2 or 3).
type PLMN struct {
	MCC string `yaml:"mcc"`
	MNC string `yaml:"mnc"`
}

// String renders "mcc-mnc" (log form, e.g. "001-02").
func (p PLMN) String() string { return p.MCC + "-" + p.MNC }

// HomePLMN is one roaming partner: its PLMN and the apiRoot of its AUSF/UDM.
type HomePLMN struct {
	PLMN        PLMN   `yaml:"plmn"`
	AUSFAPIRoot string `yaml:"ausf_api_root"`
	UDMAPIRoot  string `yaml:"udm_api_root"`
	// SMFAPIRoot is the optional apiRoot of the home SMF (H-SMF); empty = no home
	// routing for this partner (ROAM-002). Ref: TS 29.502 Table 6.1.6.2.2-1
	SMFAPIRoot string `yaml:"smf_api_root"`
}

// Config is the AMF "roaming:" YAML block. Absent or Enabled=false = off.
type Config struct {
	Enabled bool `yaml:"enabled"`
	// SEPPAddress is the local SEPP SBI listener (host:port) that is the apiRoot of
	// every roaming request.
	SEPPAddress string     `yaml:"sepp_address"`
	HomePLMNs   []HomePLMN `yaml:"home_plmns"`
	// PartnersFile is the roaming partners file (overridden by env
	// ROAMING_PARTNERS_FILE; default /etc/5gc/roaming/partners.yaml). Its
	// entries with home_nfs become home PLMNs (SEPP-005).
	PartnersFile string `yaml:"partners_file"`
}

// NF selects which home NF a hop targets.
type NF int

// Home NF kinds.
const (
	NFAUSF NF = iota
	NFUDM
)

// Hop is the resolved destination of one roaming request.
type Hop struct {
	// ViaSEPP is the local SEPP host:port the request is sent to.
	ViaSEPP string
	// APIRoot is the home NF apiRoot for the target-apiRoot header.
	APIRoot string
	// Origin is the serving (source) PLMN for the originating-network-id header.
	Origin PLMN
}

// OriginatingNetworkID returns the 3gpp-Sbi-Originating-Network-Id value
// ("mcc-mnc"), "" when the serving PLMN is unknown.
func (h Hop) OriginatingNetworkID() string {
	if h.Origin.MCC == "" {
		return ""
	}
	return h.Origin.String()
}

// URL returns the request URL: the local SEPP as apiRoot plus the SBI path.
func (h Hop) URL(path string) string { return "https://" + h.ViaSEPP + path }

// Route is the home route chosen for a UE at Phase 1 and stored on its
// context. It is never recomputed after KSEAF is derived.
type Route struct {
	HomePLMN PLMN
	// ServingPLMN is the serving (local core) PLMN of the AMF.
	ServingPLMN PLMN
	ViaSEPP     string
	AUSFAPIRoot string
	UDMAPIRoot  string
	// SMFAPIRoot is the home SMF apiRoot ("" = home routing not configured).
	SMFAPIRoot string
}

// Hop returns the destination for the given home NF.
func (r *Route) Hop(nf NF) Hop {
	if nf == NFUDM {
		return Hop{ViaSEPP: r.ViaSEPP, APIRoot: r.UDMAPIRoot, Origin: r.ServingPLMN}
	}
	return Hop{ViaSEPP: r.ViaSEPP, APIRoot: r.AUSFAPIRoot, Origin: r.ServingPLMN}
}

// OwnsSUPI reports whether the IMSI-based SUPI belongs to the route's home PLMN
// (TS 33.501 §6.1.3.2: the SUPI returned by the home AUSF is bound to the home
// network). A non-IMSI SUPI cannot be checked and is reported as not owned.
func (r *Route) OwnsSUPI(supi string) bool {
	d, ok := strings.CutPrefix(supi, "imsi-")
	return ok && strings.HasPrefix(d, r.HomePLMN.MCC+r.HomePLMN.MNC)
}

type ctxKey struct{}

type requiredKey struct{}

// WithRoamingRequired marks ctx as the request of a UE known to be roaming: a
// Nausf/Nudm client that cannot resolve a route for it must fail instead of
// falling back to the local home NF.
func WithRoamingRequired(ctx context.Context) context.Context {
	return context.WithValue(ctx, requiredKey{}, true)
}

// RoamingRequired reports whether ctx was marked by WithRoamingRequired.
func RoamingRequired(ctx context.Context) bool {
	v, _ := ctx.Value(requiredKey{}).(bool)
	return v
}

// ErrNoRoute: a roaming UE's request has no resolvable route; it is never sent
// to the local AUSF/UDM.
var ErrNoRoute = errors.New("roaming: no route for roaming UE")

// WithRoute returns ctx carrying the route; a nil route returns ctx unchanged.
func WithRoute(ctx context.Context, r *Route) context.Context {
	if r == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, r)
}

// RouteFrom returns the route carried by ctx, or nil (non-roaming).
func RouteFrom(ctx context.Context) *Route {
	r, _ := ctx.Value(ctxKey{}).(*Route)
	return r
}

// Router classifies identities and remembers the route per SUPI for the
// calls that only know the SUPI (deregistration).
type Router struct {
	cfg     Config
	serving PLMN
	mu      sync.Mutex
	bySUPI  map[string]*Route
}

// New validates cfg and builds a Router. A nil Router and nil error is
// returned when roaming is absent or disabled. Validation: sepp_address
// host:port; every home PLMN has numeric MCC (3) / MNC (2-3) and https api
// roots whose host is an FQDN with mncNNN and mccNNN labels matching the PLMN
// (TS 23.003 §28.3.2.1).
func New(cfg Config, servingMCC, servingMNC string) (*Router, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if _, port, err := net.SplitHostPort(cfg.SEPPAddress); err != nil || port == "" {
		return nil, fmt.Errorf("amf: roaming: sepp_address %q must be host:port", cfg.SEPPAddress)
	}
	seen := map[PLMN]bool{}
	for i, h := range cfg.HomePLMNs {
		if !digits(h.PLMN.MCC, 3) || !mncOK(h.PLMN.MNC) {
			return nil, fmt.Errorf("amf: roaming: home_plmns[%d]: invalid plmn %s", i, h.PLMN)
		}
		if seen[h.PLMN] {
			return nil, fmt.Errorf("amf: roaming: home_plmns[%d]: duplicate plmn %s", i, h.PLMN)
		}
		seen[h.PLMN] = true
		for _, f := range []struct{ name, v string }{{"ausf_api_root", h.AUSFAPIRoot}, {"udm_api_root", h.UDMAPIRoot}} {
			if err := validateAPIRoot(f.v, h.PLMN); err != nil {
				return nil, fmt.Errorf("amf: roaming: home_plmns[%d].%s: %w", i, f.name, err)
			}
		}
		if h.SMFAPIRoot != "" {
			if err := validateAPIRoot(h.SMFAPIRoot, h.PLMN); err != nil {
				return nil, fmt.Errorf("amf: roaming: home_plmns[%d].smf_api_root: %w", i, err)
			}
		}
	}
	return &Router{cfg: cfg, serving: PLMN{MCC: servingMCC, MNC: servingMNC}, bySUPI: map[string]*Route{}}, nil
}

// mncOK reports a 2- or 3-digit MNC. Ref: TS 23.003 §2.2
func mncOK(s string) bool { return digits(s, 2) || digits(s, 3) }

func digits(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func validateAPIRoot(root string, p PLMN) error {
	u, err := url.Parse(root)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return fmt.Errorf("%q must be an https apiRoot", root)
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("%q must not carry a path", root)
	}
	wantMNC := "mnc" + zeroPad3(p.MNC)
	wantMCC := "mcc" + p.MCC
	var hasMNC, hasMCC bool
	for _, l := range strings.Split(strings.ToLower(u.Hostname()), ".") {
		hasMNC = hasMNC || l == wantMNC
		hasMCC = hasMCC || l == wantMCC
	}
	if !hasMNC || !hasMCC || !strings.Contains(u.Hostname(), ".") {
		return fmt.Errorf("host %q must be an FQDN with labels %s and %s", u.Hostname(), wantMNC, wantMCC)
	}
	return nil
}

func zeroPad3(mnc string) string {
	for len(mnc) < 3 {
		mnc = "0" + mnc
	}
	return mnc
}

// Enabled reports whether roaming is on (false for a nil Router).
func (r *Router) Enabled() bool { return r != nil }

// SEPPAddress returns the configured SEPP address.
func (r *Router) SEPPAddress() string {
	if r == nil {
		return ""
	}
	return r.cfg.SEPPAddress
}

// Classify decides whether the identity (a TS 29.571 SUCI "suci-0-<mcc>-<mnc>-...",
// or an IMSI-based SUPI "imsi-<digits>") belongs to a roaming UE. It returns
// (nil, nil) for a non-roaming UE (also for a nil Router, a 5G-GUTI string or
// any unparsable identity: those keep today's local path), the route for a
// configured home PLMN, or ErrHomePLMNNotConfigured. No equivalent-PLMN list
// exists in the AMF today, so only the serving PLMN counts as non-roaming.
// For a SUPI the MNC length comes from the configuration (the digits are not
// self-describing), the serving PLMN being tried first.
// Ref: TS 23.501 §6.3.4; TS 24.501 §9.11.3.4
func (r *Router) Classify(identity string) (*Route, error) {
	if r == nil {
		return nil, nil
	}
	hni, ok := r.homeNetwork(identity)
	if !ok || hni == r.serving {
		return nil, nil
	}
	for _, h := range r.cfg.HomePLMNs {
		if h.PLMN == hni {
			return &Route{HomePLMN: h.PLMN, ServingPLMN: r.serving, ViaSEPP: r.cfg.SEPPAddress,
				AUSFAPIRoot: h.AUSFAPIRoot, UDMAPIRoot: h.UDMAPIRoot, SMFAPIRoot: h.SMFAPIRoot}, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrHomePLMNNotConfigured, hni)
}

// Classifiable reports whether the identity yields a home network at all (a
// SUCI of IMSI type or an IMSI-based SUPI). A 5G-GUTI or an unparsable SUCI does
// not: the caller must not treat that as "non-roaming". False for a nil Router.
func (r *Router) Classifiable(identity string) bool {
	if r == nil {
		return false
	}
	_, ok := r.homeNetwork(identity)
	return ok
}

// HomePLMNOf returns the home PLMN of the identity as "<mcc>-<mnc>" for log
// records, or "" when it cannot be derived (nil Router, GUTI, unparsable).
func (r *Router) HomePLMNOf(identity string) string {
	if r == nil {
		return ""
	}
	if p, ok := r.homeNetwork(identity); ok {
		return p.String()
	}
	return ""
}

func (r *Router) homeNetwork(identity string) (PLMN, bool) {
	switch {
	case strings.HasPrefix(identity, "suci-"):
		p := strings.Split(identity, "-")
		if len(p) < 4 || p[1] != "0" || !digits(p[2], 3) || !mncOK(p[3]) {
			return PLMN{}, false
		}
		return PLMN{MCC: p[2], MNC: p[3]}, true
	case strings.HasPrefix(identity, "imsi-"):
		d := identity[len("imsi-"):]
		cands := []PLMN{r.serving}
		for _, h := range r.cfg.HomePLMNs {
			cands = append(cands, h.PLMN)
		}
		for _, c := range cands {
			if strings.HasPrefix(d, c.MCC+c.MNC) {
				return c, true
			}
		}
		if len(d) >= 6 && digits(d[:3], 3) { // unknown home network: MNC length unknowable
			return PLMN{MCC: d[:3], MNC: d[3:5]}, true
		}
	}
	return PLMN{}, false
}

// Remember stores the route for a SUPI (used by SUPI-only deregistration calls).
// A nil route deletes the entry (a UE that re-registered as non-roaming). It
// returns false when the map is full (MaxRememberedRoutes) and the route was not
// stored; the UE context still carries its own route.
func (r *Router) Remember(supi string, rt *Route) bool {
	if r == nil || supi == "" {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if rt == nil {
		delete(r.bySUPI, supi)
		return true
	}
	if _, exists := r.bySUPI[supi]; !exists && len(r.bySUPI) >= MaxRememberedRoutes {
		return false
	}
	r.bySUPI[supi] = rt
	return true
}

// ForSUPI returns the remembered route for supi, or nil.
func (r *Router) ForSUPI(supi string) *Route {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.bySUPI[supi]
}

// Forget drops the remembered route for supi.
func (r *Router) Forget(supi string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.bySUPI, supi)
	r.mu.Unlock()
}

// FullDNN builds the full DNN (Network Identifier + Operator Identifier)
// "<dnn>.mnc<MNC 3 digits>.mcc<MCC>.gprs" of the PLMN, as required for a
// home-routed PDU session.
// Ref: TS 23.003 §9.1.2; TS 29.502 Table 6.1.6.2.2-1
func FullDNN(dnn string, p PLMN) string {
	return dnn + ".mnc" + zeroPad3(p.MNC) + ".mcc" + p.MCC + ".gprs"
}

// HSMFURI returns the H-SMF Nsmf_PDUSession API URI (apiRoot + service path),
// "" when the route has no smf_api_root (home routing not configured).
// Ref: TS 29.502 §6.1.1; Table 6.1.6.2.2-1 (hSmfUri)
func (r *Route) HSMFURI() string {
	if r == nil || r.SMFAPIRoot == "" {
		return ""
	}
	return strings.TrimSuffix(r.SMFAPIRoot, "/") + "/nsmf-pdusession/v1"
}

// HomeRouting is the home-routed PDU session descriptor the AMF hands to the
// SMF client (ROAM-002): the CreateSMContext still goes to the LOCAL SMF
// (V-SMF); these attributes make it a V-SMF and tell it which H-SMF to use.
// Ref: TS 29.502 Table 6.1.6.2.2-1; TS 23.502 §4.3.2.2.2 step 3a
type HomeRouting struct {
	// HSMFURI is the API URI of the H-SMF ("hSmfUri").
	HSMFURI string
	// FullDNN is the full DNN of the home PLMN ("dnn").
	FullDNN string
	// HPLMNSST / HPLMNSD are the HPLMN S-NSSAI ("hplmnSnssai"); identity mapping.
	HPLMNSST uint8
	HPLMNSD  string
}

type homeRoutingKey struct{}

// WithHomeRouting returns ctx carrying the home-routing descriptor. The context
// keeps the SMFClient/CallSMF signatures (and every non-roaming byte) unchanged.
func WithHomeRouting(ctx context.Context, hr HomeRouting) context.Context {
	return context.WithValue(ctx, homeRoutingKey{}, hr)
}

// HomeRoutingFrom returns the descriptor set by WithHomeRouting.
func HomeRoutingFrom(ctx context.Context) (HomeRouting, bool) {
	hr, ok := ctx.Value(homeRoutingKey{}).(HomeRouting)
	return hr, ok
}

// NewHomeRouting builds the descriptor for a session of the route's UE; false
// when the route is nil or has no smf_api_root.
// Ref: TS 23.003 §9.1.2; TS 29.502 Table 6.1.6.2.2-1
func (r *Route) NewHomeRouting(dnn string, sst uint8, sd string) (HomeRouting, bool) {
	uri := r.HSMFURI()
	if uri == "" {
		return HomeRouting{}, false
	}
	return HomeRouting{HSMFURI: uri, FullDNN: FullDNN(dnn, r.HomePLMN), HPLMNSST: sst, HPLMNSD: sd}, true
}
