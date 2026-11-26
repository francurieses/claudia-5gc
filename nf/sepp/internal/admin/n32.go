// Package admin hosts the SEPP's O&M HTTP handlers for the N32 status view
// (task PORTAL-UI-22). They are mounted on the internal metrics port
// (shared/observability/metrics MetricsServerWithAdmin), never on the N32 or
// SBI listeners: the routes carry no authentication.
//
//	GET  /admin/v1/n32/contexts                      read-only N32 context view
//	POST /admin/v1/n32/contexts/{mcc-mnc}/handshake  re-run N32-c exchange-capability (initiator)
//	POST /admin/v1/n32/contexts/{mcc-mnc}/teardown   N32-f TLS teardown (NONE, needs NFTLST)
//	GET  /admin/v1/n32/partners                      effective roaming partners + trust anchors (read-only)
//
// It is project tooling, not a 3GPP service; the data it reads is the PLMN to
// N32 connection mapping of TS 29.573 §5.2.2.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/francurieses/claudia-5gc/nf/sepp/internal/config"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32c"
	"github.com/francurieses/claudia-5gc/nf/sepp/internal/n32trust"
	"github.com/francurieses/claudia-5gc/shared/logging"
)

const (
	// ContextsPath is the read-only N32 context view.
	ContextsPath = "/admin/v1/n32/contexts"
	// PartnersPath is the read-only effective roaming-partner view (SEPP-005).
	PartnersPath = "/admin/v1/n32/partners"
	// ContextsSubtree is the ServeMux pattern of the per-PLMN actions.
	ContextsSubtree = ContextsPath + "/"
	// actionTimeout bounds one handshake/teardown triggered by an operator.
	actionTimeout = 15 * time.Second
	// procedure is the canonical log procedure of operator-triggered actions.
	procedure = "N32cOperatorAction"
	// specRef anchors the data model (PLMN to N32 connection mapping).
	specRef = "TS 29.573 §5.2.2"
	// stateEstablished / stateNone are the context states reported per partner.
	stateEstablished = "ESTABLISHED"
	stateNone        = "NONE"
)

// N32 is the n32c.Service surface the handlers need; *n32c.Service implements it.
type N32 interface {
	Store() *n32c.Store
	Partners() []n32c.PlmnId
	LastAttempt(p n32c.PlmnId) (n32c.Attempt, bool)
	LocalPLMN() n32c.PlmnId
	LocalFQDN() string
	Exchange(ctx context.Context, peerAPIRoot string, target n32c.PlmnId) (n32c.Context, error)
	Teardown(ctx context.Context, peerAPIRoot string, remote n32c.PlmnId) error
}

// Info is the static part of the view.
type Info struct {
	ReleaseProfile string
	TopologyHiding bool
	// Partners are the effective N32 partners (config.Config.N32Partners);
	// those with an address are the N32-c initiator targets.
	Partners []config.Partner
	// Anchors are the loaded trust anchors (n32trust.Verifier.Anchors).
	Anchors []n32trust.AnchorInfo
}

// PartnerInfo is one effective roaming partner in GET /admin/v1/n32/partners.
type PartnerInfo struct {
	PLMN           string     `json:"plmn"`
	Source         string     `json:"source"`
	CAFile         string     `json:"caFile"`
	SEPPFQDN       string     `json:"seppFqdn"`
	Address        string     `json:"address"`
	AnchorSubject  string     `json:"anchorSubject,omitempty"`
	AnchorNotAfter *time.Time `json:"anchorNotAfter,omitempty"`
}

// ServePartners serves GET PartnersPath. It needs no N32-c service: the list
// is the loaded configuration.
func (h *Handler) ServePartners(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeProblem(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET only")
		return
	}
	out := struct {
		Partners []PartnerInfo `json:"partners"`
	}{Partners: []PartnerInfo{}}
	for _, p := range h.info.Partners {
		pi := PartnerInfo{PLMN: p.PLMN.String(), Source: p.Source, CAFile: p.N32.CAFile,
			SEPPFQDN: p.FQDN(), Address: p.N32.Address}
		for _, a := range h.info.Anchors {
			if a.PLMN == pi.PLMN {
				na := a.NotAfter.UTC()
				pi.AnchorSubject, pi.AnchorNotAfter = a.Subject, &na
			}
		}
		out.Partners = append(out.Partners, pi)
	}
	writeJSON(w, http.StatusOK, out)
}

// PartnerView is one roaming partner in the GET response.
type PartnerView struct {
	PLMN                string        `json:"plmn"`
	State               string        `json:"state"`
	Initiator           bool          `json:"initiator"`
	PeerFQDN            string        `json:"peer_fqdn,omitempty"`
	PeerAddress         string        `json:"peer_address,omitempty"`
	Security            string        `json:"security,omitempty"`
	TargetAPIRootHeader bool          `json:"target_api_root_header"`
	NFTLST              bool          `json:"nftlst"`
	NegotiatedFeatures  string        `json:"negotiated_features,omitempty"`
	EstablishedAt       *time.Time    `json:"established_at,omitempty"`
	LastAttempt         *n32c.Attempt `json:"last_attempt,omitempty"`
}

// ContextsView is the GET /admin/v1/n32/contexts body.
type ContextsView struct {
	NF             string        `json:"nf"`
	LocalPLMN      string        `json:"local_plmn"`
	LocalFQDN      string        `json:"local_fqdn"`
	ReleaseProfile string        `json:"release_profile"`
	SecurityMode   string        `json:"security_mode"`
	TopologyHiding bool          `json:"topology_hiding"`
	Established    int           `json:"established"`
	Partners       []PartnerView `json:"partners"`
	GeneratedAt    time.Time     `json:"generated_at"`
}

// Handler serves the N32 admin routes.
type Handler struct {
	n32    N32
	info   Info
	logger *slog.Logger
	now    func() time.Time
}

// NewHandler returns the handler; svc nil (N32-c disabled) yields 503s.
func NewHandler(svc N32, info Info, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{n32: svc, info: info, logger: logger, now: time.Now}
}

// ServeHTTP dispatches GET on ContextsPath and POST on the per-PLMN actions.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.n32 == nil {
		writeProblem(w, http.StatusServiceUnavailable, "N32_DISABLED", "N32-c service is not configured")
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, ContextsPath), "/")
	if rest == "" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeProblem(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET only")
			return
		}
		writeJSON(w, http.StatusOK, h.view())
		return
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || (parts[1] != "handshake" && parts[1] != "teardown") {
		writeProblem(w, http.StatusNotFound, "RESOURCE_NOT_FOUND", "unknown admin path")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeProblem(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST only")
		return
	}
	plmn, ok := parsePLMN(parts[0])
	if !ok {
		writeProblem(w, http.StatusBadRequest, "INVALID_PLMN", "PLMN must be mcc-mnc, e.g. 001-02")
		return
	}
	h.action(w, r, plmn, parts[1])
}

func (h *Handler) view() ContextsView {
	byKey := map[string]n32c.Context{}
	for _, c := range h.n32.Store().Snapshot() {
		byKey[c.RemotePLMN.Key()] = c
	}
	v := ContextsView{
		NF: "SEPP", LocalPLMN: h.n32.LocalPLMN().String(), LocalFQDN: h.n32.LocalFQDN(),
		ReleaseProfile: h.info.ReleaseProfile, SecurityMode: string(n32c.CapTLS),
		TopologyHiding: h.info.TopologyHiding, Partners: []PartnerView{}, GeneratedAt: h.now().UTC(),
	}
	for _, p := range h.n32.Partners() {
		pv := PartnerView{PLMN: p.String(), State: stateNone}
		if peer, ok := h.peer(p); ok {
			pv.Initiator, pv.PeerFQDN, pv.PeerAddress = true, peer.FQDN, peer.Address
		}
		if c, ok := byKey[p.Key()]; ok {
			at := c.CreatedAt.UTC()
			pv.State, pv.Security, pv.EstablishedAt = stateEstablished, string(c.SecCapability), &at
			pv.TargetAPIRootHeader, pv.NFTLST = c.TargetAPIRootHeader, c.NFTLST
			pv.NegotiatedFeatures = c.Features.String()
			if c.PeerFQDN != "" {
				pv.PeerFQDN = c.PeerFQDN
			}
			v.Established++
		}
		if a, ok := h.n32.LastAttempt(p); ok {
			a.At = a.At.UTC()
			pv.LastAttempt = &a
		}
		v.Partners = append(v.Partners, pv)
	}
	return v
}

// peerTarget is the initiator target (partner with an address) of a PLMN.
type peerTarget struct{ FQDN, Address string }

// peer returns the initiator target of p (a partner with n32.address).
func (h *Handler) peer(p n32c.PlmnId) (peerTarget, bool) {
	for _, q := range h.info.Partners {
		if q.N32.Address != "" && (n32c.PlmnId{Mcc: q.PLMN.MCC, Mnc: q.PLMN.MNC}).Key() == p.Key() {
			return peerTarget{FQDN: q.FQDN(), Address: q.N32.Address}, true
		}
	}
	return peerTarget{}, false
}

func (h *Handler) action(w http.ResponseWriter, r *http.Request, plmn n32c.PlmnId, act string) {
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	lg := logging.NewProcedureLogger(ctx, h.logger, procedure).With(
		"nf", "SEPP", "interface", "N32c", "direction", "OUT", "peer_plmn", plmn.String(),
		"action", act, "spec_ref", specRef)
	peer, ok := h.peer(plmn)
	if !ok {
		writeProblem(w, http.StatusConflict, "NO_PEER_CONFIGURED",
			"no n32.address for this partner PLMN: this SEPP only answers its handshakes")
		return
	}
	ctx, cancel := context.WithTimeout(ctx, actionTimeout)
	defer cancel()
	apiRoot := "https://" + peer.Address
	var err error
	if act == "handshake" {
		_, err = h.n32.Exchange(ctx, apiRoot, plmn)
	} else {
		err = h.n32.Teardown(ctx, apiRoot, plmn)
	}
	if err != nil {
		status, cause := http.StatusBadGateway, "N32C_EXCHANGE_FAILED"
		if errors.Is(err, n32c.ErrTeardownNotAllowed) {
			status, cause = http.StatusConflict, "TEARDOWN_NOT_ALLOWED"
		}
		lg.WarnContext(ctx, "operator-triggered N32-c action failed", "result", "FAILURE", "cause", err.Error())
		writeProblem(w, status, cause, err.Error())
		return
	}
	lg.InfoContext(ctx, "operator-triggered N32-c action completed", "result", "OK")
	writeJSON(w, http.StatusOK, h.view())
}

// parsePLMN accepts "mcc-mnc" (also "mcc/mnc").
func parsePLMN(s string) (n32c.PlmnId, bool) {
	s = strings.ReplaceAll(s, "/", "-")
	mcc, mnc, ok := strings.Cut(s, "-")
	p := n32c.PlmnId{Mcc: mcc, Mnc: mnc}
	return p, ok && p.Valid()
}

type problem struct {
	Title  string `json:"title"`
	Status int    `json:"status"`
	Cause  string `json:"cause"`
	Detail string `json:"detail"`
}

func writeProblem(w http.ResponseWriter, status int, cause, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem{Title: http.StatusText(status), Status: status, Cause: cause, Detail: detail})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
