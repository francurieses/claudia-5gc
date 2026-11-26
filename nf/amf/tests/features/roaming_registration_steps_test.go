//go:build functional

// In-process step definitions for roaming_registration.feature (ROAM-001: visited
// AMF, home-controlled authentication and registration over N32; TS 23.502
// §4.2.2.2.2, TS 33.501 §6.1.3.2 / §6.1.1.4, TS 29.500 §6.1.4.3, TS 23.501 §6.3.4).
//
// The AMF side is the real nasmsg.Handler + procedures.RegistrationHandler with
// roaming.Router, driven through HandleNASMessage. The SEPP, the local AUSF and
// the local UDM are httptest TLS servers that record every request. The UE side
// reuses the NAS-security helpers of nas_security_algorithms_steps_test.go
// (nsaWorld: UL protection, DL deciphering, SMC parsing).
//
// Limitation: the production Nausf/Nudm clients (HTTPAUSFClient/HTTPUDMClient)
// are declared in package main and cannot be imported here. The rrAUSF/rrUDM
// clients below are test-side peers of the RegistrationHandler that turn the
// roaming.Route found on the request context into "request to the SEPP with
// 3gpp-Sbi-Target-apiRoot" exactly as cmd/amf/roaming_route.go does. The wire
// of the production clients is asserted in cmd/amf/roaming_route_test.go; this
// suite asserts what the handler and the NAS layer do with the route (selection,
// context, per-phase propagation, reject causes, logs).
package features_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/cucumber/godog"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	nasmsg "github.com/francurieses/claudia-5gc/nf/amf/internal/nas"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/roaming"
	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

const (
	rrSUPILocal = "imsi-001010000000001" // answered by the local AUSF
	rrSUPIHome  = "imsi-001020000000001" // answered by the home AUSF through the SEPP
	rrAUSFPath  = "/nausf-auth/v1/ue-authentications"
)

// rrReq is one request received by a mock.
type rrReq struct {
	method, uri, ctype, body string
	apiRoot                  string
	hasHdr                   bool
}

// rrServer is an httptest TLS mock recording its requests.
type rrServer struct {
	role string
	srv  *httptest.Server
	addr string // host:port
	cert *x509.Certificate

	mu   sync.Mutex
	reqs []rrReq
}

func (s *rrServer) snapshot() []rrReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]rrReq(nil), s.reqs...)
}

func (s *rrServer) find(method, uriPrefix, uriSuffix string) *rrReq {
	for _, r := range s.snapshot() {
		if r.method == method && strings.HasPrefix(r.uri, uriPrefix) && strings.HasSuffix(r.uri, uriSuffix) {
			c := r
			return &c
		}
	}
	return nil
}

// rrWorld is the per-scenario state.
type rrWorld struct {
	// Background configuration (handler is built lazily on the first When).
	mcc, mnc       string
	snn            string
	seppEnabled    bool // "roaming enabled, sepp_address = SEPP mock"
	noRoamingBlock bool
	homes          []roaming.HomePLMN
	gnbPLMN        string

	sepp, lausf, ludm *rrServer
	httpc             *http.Client

	// SEPP behaviour overrides.
	authInitStatus int
	authInitCause  string
	allReqStatus   int // 504 for every request
	allReqCause    string
	uecmStatus     int
	uecmCause      string
	seppClosed     bool

	// UE.
	homePLMN string // "001/02"
	supi     string // SUPI the answering AUSF returned (UE key derivation)

	rp      rpState // roaming_partners_file.feature (SEPP-005)
	logs    *nsaSyncBuf
	nw      *nsaWorld
	rtr     *roaming.Router
	stage   int // 1 reg sent, 2 auth response sent, 3 SMC complete sent
	last    *rrReq
	udmReqs []*rrReq
}

var rrW *rrWorld

func (w *rrWorld) newServer(role string) (*rrServer, error) {
	s := &rrServer{role: role}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_, has := r.Header[http.CanonicalHeaderKey(roaming.TargetAPIRootHeader)]
		rq := rrReq{method: r.Method, uri: r.URL.RequestURI(), ctype: r.Header.Get("Content-Type"),
			body: string(raw), apiRoot: r.Header.Get(roaming.TargetAPIRootHeader), hasHdr: has}
		s.mu.Lock()
		s.reqs = append(s.reqs, rq)
		s.mu.Unlock()
		status, loc, out := w.answer(role, rq)
		rw.Header().Set("Content-Type", "application/json")
		if loc != "" {
			rw.Header().Set("Location", loc)
		}
		rw.WriteHeader(status)
		_, _ = rw.Write([]byte(out))
	}))
	s.addr = strings.TrimPrefix(s.srv.URL, "https://")
	s.cert = s.srv.Certificate()
	return s, nil
}

func rrProblem(cause string) string { return `{"cause":"` + cause + `"}` }

// answer is the behaviour of a mock. The local mocks always answer normally; the
// SEPP plays the SEPP+hSEPP+home NF chain unless an override says otherwise.
func (w *rrWorld) answer(role string, rq rrReq) (int, string, string) {
	supi := rrSUPILocal
	if role == "sepp" {
		supi = rrSUPIHome
		if w.allReqStatus != 0 {
			return w.allReqStatus, "", rrProblem(w.allReqCause)
		}
	}
	switch {
	case rq.method == "POST" && rq.uri == rrAUSFPath:
		if role == "sepp" && w.authInitStatus != 0 {
			return w.authInitStatus, "", rrProblem(w.authInitCause)
		}
		return 201, "https://ausf/nausf-auth/v1/ue-authentications/ctx-1", `{"authCtxId":"ctx-1",` +
			`"rand":"000102030405060708090a0b0c0d0e0f","autn":"101112131415161718191a1b1c1d1e1f",` +
			`"hxresStar":"202122232425262728292a2b2c2d2e2f","supi":"` + supi + `"}`
	case rq.method == "PUT" && strings.HasSuffix(rq.uri, "/5g-aka-confirmation"):
		return 200, "", `{"authResult":"AUTHENTICATION_SUCCESS","supi":"` + supi + `","kausf":"` +
			hex.EncodeToString(nsaKAUSF) + `"}`
	case rq.method == "PUT" && strings.Contains(rq.uri, "/nudm-uecm/"):
		if role == "sepp" && w.uecmStatus != 0 {
			return w.uecmStatus, "", rrProblem(w.uecmCause)
		}
		return 201, "", `{}`
	case rq.method == "GET" && strings.HasSuffix(rq.uri, "/am-data"):
		return 200, "", `{"sst":1}`
	case rq.method == "POST" && strings.HasSuffix(rq.uri, "/sdm-subscriptions"):
		return 201, "", `{"subscriptionId":"sub-1"}`
	}
	return 404, "", rrProblem("UNEXPECTED_REQUEST")
}

// ---- test-side Nausf / Nudm clients ---------------------------------------

type rrHTTP struct {
	w     *rrWorld
	local func() *rrServer
	nf    roaming.NF
}

// do sends one SBI request: to the local peer, or - when ctx carries a roaming
// route - to the SEPP with 3gpp-Sbi-Target-apiRoot (TS 29.500 §6.1.4.3).
func (c *rrHTTP) do(ctx context.Context, method, path string, body any) (int, http.Header, []byte, error) {
	url := "https://" + c.local().addr + path
	var hop *roaming.Hop
	if rt := roaming.RouteFrom(ctx); rt != nil {
		h := rt.Hop(c.nf)
		hop = &h
		url = h.URL(path)
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return 0, nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if hop != nil {
		req.Header.Set(roaming.TargetAPIRootHeader, hop.APIRoot)
	}
	resp, err := c.w.httpc.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, raw, nil
}

func rrCause(raw []byte) string {
	var p struct {
		Cause string `json:"cause"`
	}
	_ = json.Unmarshal(raw, &p)
	return p.Cause
}

type rrAUSF struct{ rrHTTP }

func (a *rrAUSF) InitiateAuth(ctx context.Context, suci, snn string) (*procedures.AUSFInitResponse, error) {
	st, _, raw, err := a.do(ctx, "POST", rrAUSFPath,
		map[string]string{"supiOrSuci": suci, "servingNetworkName": snn})
	if err != nil {
		return nil, fmt.Errorf("ausf: initiate auth: %w", err)
	}
	if st != http.StatusCreated {
		return nil, &procedures.AUSFError{Op: "initiate auth", Status: st, Cause: rrCause(raw)}
	}
	var v struct{ AuthCtxID, Rand, Autn, HxresStar, Supi string }
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	v.AuthCtxID, v.Rand, v.Autn, v.HxresStar, v.Supi = m["authCtxId"], m["rand"], m["autn"], m["hxresStar"], m["supi"]
	out := &procedures.AUSFInitResponse{AuthCtxID: v.AuthCtxID, SUPI: v.Supi}
	r, _ := hex.DecodeString(v.Rand)
	copy(out.RAND[:], r)
	u, _ := hex.DecodeString(v.Autn)
	copy(out.AUTN[:], u)
	out.HXRESStar, _ = hex.DecodeString(v.HxresStar)
	a.w.supi = v.Supi
	return out, nil
}

func (a *rrAUSF) ResyncAuth(context.Context, string, string, [16]byte, []byte) (*procedures.AUSFInitResponse, error) {
	return nil, errors.New("rrAUSF: resync not used by roaming_registration.feature")
}

func (a *rrAUSF) ConfirmAuth(ctx context.Context, id, resStar string) (*procedures.AUSFConfirmResponse, error) {
	st, _, raw, err := a.do(ctx, "PUT", rrAUSFPath+"/"+id+"/5g-aka-confirmation", map[string]string{"resStar": resStar})
	if err != nil {
		return nil, fmt.Errorf("ausf: confirm auth: %w", err)
	}
	if st != http.StatusOK {
		return nil, &procedures.AUSFError{Op: "confirm auth", Status: st, Cause: rrCause(raw)}
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	k, _ := hex.DecodeString(m["kausf"])
	return &procedures.AUSFConfirmResponse{SUPI: m["supi"], KAUSF: k}, nil
}

type rrUDM struct{ rrHTTP }

func (u *rrUDM) fail(op string, st int, raw []byte, err error) error {
	if err != nil {
		return &procedures.UDMError{Op: op, Err: err}
	}
	return &procedures.UDMError{Op: op, Status: st, Cause: rrCause(raw)}
}

func (u *rrUDM) RegisterAMF(ctx context.Context, supi, amfID, snn string) error {
	st, _, raw, err := u.do(ctx, "PUT", "/nudm-uecm/v1/"+supi+"/registrations/amf-3gpp-access",
		map[string]string{"amfInstanceId": amfID, "servingNetworkName": snn})
	if err != nil || st/100 != 2 {
		return u.fail("uecm register", st, raw, err)
	}
	return nil
}

func (u *rrUDM) GetAMSubscriptionData(ctx context.Context, supi string) (*procedures.UDMAMSubscription, error) {
	st, _, raw, err := u.do(ctx, "GET", "/nudm-sdm/v2/"+supi+"/am-data", nil)
	if err != nil || st != http.StatusOK {
		return nil, u.fail("sdm get am-data", st, raw, err)
	}
	s := []amfctx.SNSSAISubscribed{{SST: 1}}
	return &procedures.UDMAMSubscription{AllowedNSSAI: s, DefaultNSSAI: s}, nil
}

func (u *rrUDM) DeregisterUECM(ctx context.Context, supi string) error {
	st, _, raw, err := u.do(ctx, "DELETE", "/nudm-uecm/v1/"+supi+"/registrations/amf-3gpp-access", nil)
	if err != nil || st/100 != 2 {
		return u.fail("uecm deregister", st, raw, err)
	}
	return nil
}

func (u *rrUDM) SubscribeAMData(ctx context.Context, supi string) (string, error) {
	st, _, raw, err := u.do(ctx, "POST", "/nudm-sdm/v2/"+supi+"/sdm-subscriptions", map[string]string{"nfInstanceId": "nf"})
	if err != nil || st != http.StatusCreated {
		return "", u.fail("sdm subscribe", st, raw, err)
	}
	return "sub-1", nil
}

func (u *rrUDM) UnsubscribeSDM(context.Context, string, string) error { return nil }

// ---- Background -----------------------------------------------------------

func rrSplitPLMN(s string) (string, string, error) {
	p := strings.Split(s, "/")
	if len(p) != 2 {
		return "", "", fmt.Errorf("PLMN %q is not MCC/MNC", s)
	}
	return p[0], p[1], nil
}

func rrServes(plmn, snn string) error {
	mcc, mnc, err := rrSplitPLMN(plmn)
	if err != nil {
		return err
	}
	rrW = &rrWorld{mcc: mcc, mnc: mnc, snn: snn, logs: &nsaSyncBuf{}}
	return nil
}

func rrMocksRunning() error {
	w := rrW
	var err error
	if w.sepp, err = w.newServer("sepp"); err != nil {
		return err
	}
	if w.lausf, err = w.newServer("local-ausf"); err != nil {
		return err
	}
	if w.ludm, err = w.newServer("local-udm"); err != nil {
		return err
	}
	pool := x509.NewCertPool()
	for _, s := range []*rrServer{w.sepp, w.lausf, w.ludm} {
		pool.AddCert(s.cert)
	}
	w.httpc = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool}, DisableKeepAlives: true}}
	return nil
}

func rrRoamingEnabled() error {
	rrW.seppEnabled = true
	return nil
}

func rrKnowsHome(plmn, ausf, udm string) error {
	mcc, mnc, err := rrSplitPLMN(plmn)
	if err != nil {
		return err
	}
	rrW.homes = append(rrW.homes, roaming.HomePLMN{PLMN: roaming.PLMN{MCC: mcc, MNC: mnc},
		AUSFAPIRoot: ausf, UDMAPIRoot: udm})
	return nil
}

func rrGNBConnected(plmn string) error {
	if plmn != rrW.mcc+"/"+rrW.mnc {
		return fmt.Errorf("gNB PLMN %s differs from the serving PLMN %s/%s", plmn, rrW.mcc, rrW.mnc)
	}
	rrW.gnbPLMN = plmn
	return nil
}

// ---- Givens ----------------------------------------------------------------

func rrNoRoamingBlock() error {
	rrW.noRoamingBlock = true
	return nil
}

func rrUEWithSUCI(plmn string) error {
	if _, _, err := rrSplitPLMN(plmn); err != nil {
		return err
	}
	rrW.homePLMN = plmn
	return nil
}

// rrUEAuthorized: the default SEPP behaviour is "home network authorizes the
// serving network", so the step only fixes the SUCI.
func rrUEAuthorized(plmn string) error { return rrUEWithSUCI(plmn) }

func rrRelayAUSF(status int, cause string) error {
	rrW.authInitStatus, rrW.authInitCause = status, cause
	return nil
}

func rrRelay504(cause string) error {
	rrW.allReqStatus, rrW.allReqCause = 504, cause
	return nil
}

func rrRelayUECM(status int, cause string) error {
	rrW.uecmStatus, rrW.uecmCause = status, cause
	return nil
}

func rrCloseVSEPP() error {
	rrW.seppClosed = true
	rrW.sepp.srv.Close()
	return nil
}

// ---- AMF + UE driving --------------------------------------------------------

func (w *rrWorld) build() error {
	if w.nw != nil {
		return nil
	}
	if w.homePLMN == "" {
		return errors.New("no UE SUCI configured (missing Given step)")
	}
	lg := slog.New(slog.NewJSONHandler(w.logs, nil))
	if w.seppEnabled && !w.noRoamingBlock {
		rtr, err := w.newRouter(lg)
		if err != nil {
			return fmt.Errorf("roaming.New: %w", err)
		}
		w.rtr = rtr
	}
	sender := &nsaSender{}
	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: w.mcc, MNC: w.mnc, AMFRegionID: 2, AMFID: 1}, nil, nil, nil)
	reg := procedures.NewRegistrationHandler(mgr,
		&rrAUSF{rrHTTP{w, func() *rrServer { return w.lausf }, roaming.NFAUSF}},
		&rrUDM{rrHTTP{w, func() *rrServer { return w.ludm }, roaming.NFUDM}},
		nil, "nf", w.mcc, w.mnc, lg)
	if w.rtr != nil {
		reg.WithRoaming(w.rtr)
	}
	h := nasmsg.NewHandler(sender, reg, lg)
	nw := &nsaWorld{sender: sender, logs: w.logs, mgr: mgr, reg: reg, h: h,
		ea: [4]bool{true, true, true, false}, ia: [4]bool{false, true, true, false}}
	nw.ue = nw.newUE(1)
	w.nw = nw
	return nil
}

// suciIdentity is a null-scheme SUCI mobile identity LV-E of the UE's home PLMN
// (TS 24.501 §9.11.3.4; PLMN octets per TS 24.008 §10.5.1.13).
func (w *rrWorld) suciIdentity() ([]byte, error) {
	mcc, mnc, err := rrSplitPLMN(w.homePLMN)
	if err != nil {
		return nil, err
	}
	if len(mcc) != 3 || len(mnc) != 2 {
		return nil, fmt.Errorf("test SUCI supports 3-digit MCC / 2-digit MNC, got %s", w.homePLMN)
	}
	d := func(s string, i int) byte { return s[i] - '0' }
	v := []byte{0x01, d(mcc, 1)<<4 | d(mcc, 0), 0xf0 | d(mcc, 2), d(mnc, 1)<<4 | d(mnc, 0),
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}
	return append([]byte{0x00, byte(len(v))}, v...), nil
}

func (w *rrWorld) sendRegistration() error {
	if w.stage >= 1 {
		return nil
	}
	if err := w.build(); err != nil {
		return err
	}
	id, err := w.suciIdentity()
	if err != nil {
		return err
	}
	e, i := nsaCapOctets(w.nw.ea, w.nw.ia)
	pdu := []byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeRegistrationRequest), 0x71}
	pdu = append(pdu, id...)
	pdu = append(pdu, 0x2E, 0x04, e, i, 0x00, 0x00)
	w.stage = 1
	// A REGISTRATION REJECT is an expected outcome: the handler returns the
	// reject cause as error, which the scenario asserts on the DL PDU instead.
	_ = w.nw.handle(pdu)
	return nil
}

func rrSendRegistration(typ, _ string) error {
	if typ != "initial" {
		return fmt.Errorf("unsupported Registration Request type %q", typ)
	}
	return rrW.sendRegistration()
}

func rrSendRegistrationFull(_ string) error {
	if err := rrW.sendRegistration(); err != nil {
		return err
	}
	return rrW.driveToEnd()
}

func (w *rrWorld) dl() [][]byte { return w.nw.sender.snapshot() }

func (w *rrWorld) hasMsg(mt byte) bool {
	for _, p := range w.dl() {
		if len(p) > 2 && p[0] == nas.PDMobilityManagement && p[1] == 0x00 && p[2] == mt {
			return true
		}
	}
	return false
}

func (w *rrWorld) sendAuthResponse() error {
	if err := w.sendRegistration(); err != nil {
		return err
	}
	if w.stage >= 2 {
		return nil
	}
	if !w.hasMsg(nsaMsgAR) {
		return fmt.Errorf("no AUTHENTICATION REQUEST was sent to the UE (DL = %x)", w.dl())
	}
	w.stage = 2
	before := len(w.dl())
	resStar := append([]byte{0x2D, 0x10}, bytes.Repeat([]byte{0x5c}, 16)...)
	_ = w.nw.handle(nsaPlain5GMM(nas.MsgTypeAuthenticationResponse, resStar...))
	// capture the SMC and derive the UE keys independently of the AMF
	for i := before; i < len(w.dl()); i++ {
		p := w.dl()[i]
		if len(p) > 10 && p[1]&0x0F == byte(nas.SecurityHeaderIntegrityProtectedWithNewSC) &&
			p[7] == nas.PDMobilityManagement && p[9] == nsaMsgSC {
			w.nw.smc, w.nw.smcMark = p, i
			w.nw.intAlg = p[10] & 0x0F
			alg := p[10] >> 4
			kseaf := kdf.KSEAF(nsaKAUSF, w.snn)
			w.nw.kamf = kdf.KAMF(kseaf, strings.TrimPrefix(w.supi, "imsi-"), [2]byte{0, 0})
			w.nw.alg = alg
			w.nw.knasenc = kdf.KNASenc(w.nw.kamf, alg)
			w.nw.knasint = kdf.KNASint(w.nw.kamf, w.nw.nia())
		}
	}
	return nil
}

func (w *rrWorld) completeSMC() error {
	if err := w.sendAuthResponse(); err != nil {
		return err
	}
	if w.stage >= 3 || w.nw.smc == nil {
		return nil // rejected before the SMC: nothing more for the UE to answer
	}
	w.stage = 3
	pdu, err := w.nw.ulProtect(nsaPlain5GMM(nas.MsgTypeSecurityModeComplete), true, true)
	if err != nil {
		return err
	}
	_ = w.nw.handle(pdu)
	return nil
}

// driveToEnd plays the UE through every downlink message the AMF is waiting for.
func (w *rrWorld) driveToEnd() error {
	if err := w.sendRegistration(); err != nil {
		return err
	}
	if w.hasReject() >= 0 {
		return nil
	}
	if err := w.sendAuthResponse(); err != nil {
		return err
	}
	if w.hasReject() >= 0 {
		return nil
	}
	return w.completeSMC()
}

// reject returns the 5GMM cause of the REGISTRATION REJECT the AMF sent, -1 if none.
func (w *rrWorld) hasReject() int {
	for _, p := range w.dl() {
		if len(p) >= 4 && p[0] == nas.PDMobilityManagement && p[1] == 0x00 && p[2] == nsaMsgRR {
			return int(p[3])
		}
		if len(p) > 7 && p[1]&0x0F == byte(nas.SecurityHeaderIntegrityProtectedAndCiphered) && w.nw.knasenc != nil {
			plain, err := w.nw.ueDecipherDL(p, w.nw.alg)
			if err == nil && len(plain) >= 4 && plain[0] == nas.PDMobilityManagement && plain[2] == nsaMsgRR {
				return int(plain[3])
			}
		}
	}
	return -1
}

func (w *rrWorld) hasAccept() bool {
	for _, p := range w.dl() {
		if len(p) > 7 && p[1]&0x0F == byte(nas.SecurityHeaderIntegrityProtectedAndCiphered) && w.nw.knasenc != nil {
			plain, err := w.nw.ueDecipherDL(p, w.nw.alg)
			if err == nil && len(plain) >= 3 && plain[0] == nas.PDMobilityManagement && plain[2] == nsaMsgRA {
				return true
			}
		}
	}
	return false
}

func rrUEAnswersAuth() error { return rrW.sendAuthResponse() }

// ---- Thens: SBI ------------------------------------------------------------

func rrVSEPPGotAuthPOST() error {
	r := rrW.sepp.find("POST", rrAUSFPath, "")
	if r == nil || r.uri != rrAUSFPath {
		return fmt.Errorf("SEPP mock did not receive POST %s (got %v)", rrAUSFPath, rrW.sepp.snapshot())
	}
	rrW.last = r
	return nil
}

func rrVSEPPGotConfirm() error {
	if err := rrW.sendAuthResponse(); err != nil {
		return err
	}
	r := rrW.sepp.find("PUT", rrAUSFPath+"/", "/5g-aka-confirmation")
	if r == nil {
		return fmt.Errorf("SEPP mock did not receive PUT 5g-aka-confirmation (got %v)", rrW.sepp.snapshot())
	}
	rrW.last = r
	return nil
}

func rrLastCarries(hdr, want string) error {
	if rrW.last == nil {
		return errors.New("no request selected by the previous step")
	}
	if hdr != roaming.TargetAPIRootHeader {
		return fmt.Errorf("unexpected header %q", hdr)
	}
	if !rrW.last.hasHdr || rrW.last.apiRoot != want {
		return fmt.Errorf("%s %s carries %s=%q (present=%v), want %q", rrW.last.method, rrW.last.uri,
			hdr, rrW.last.apiRoot, rrW.last.hasHdr, want)
	}
	return nil
}

func rrBodySNN(want string) error {
	if rrW.last == nil {
		return errors.New("no request selected by the previous step")
	}
	var b map[string]any
	if err := json.Unmarshal([]byte(rrW.last.body), &b); err != nil {
		return fmt.Errorf("request body is not JSON: %w", err)
	}
	if b["servingNetworkName"] != want {
		return fmt.Errorf("servingNetworkName = %v, want %q (body %s)", b["servingNetworkName"], want, rrW.last.body)
	}
	return nil
}

func rrUDMRequestsReachVSEPP() error {
	if err := rrW.driveToEnd(); err != nil {
		return err
	}
	w := rrW
	var sel []*rrReq
	for _, q := range []struct{ m, pfx, sfx string }{
		{"PUT", "/nudm-uecm/", "/registrations/amf-3gpp-access"},
		{"GET", "/nudm-sdm/", "/am-data"},
		{"POST", "/nudm-sdm/", "/sdm-subscriptions"},
	} {
		r := w.sepp.find(q.m, q.pfx, q.sfx)
		if r == nil {
			return fmt.Errorf("SEPP mock did not receive %s %s*%s (got %v)", q.m, q.pfx, q.sfx, w.sepp.snapshot())
		}
		sel = append(sel, r)
	}
	w.udmReqs = sel
	return nil
}

func rrUDMRequestsCarry(hdr, want string) error {
	if hdr != roaming.TargetAPIRootHeader {
		return fmt.Errorf("unexpected header %q", hdr)
	}
	if len(rrW.udmReqs) == 0 {
		return errors.New("no UDM requests selected by the previous step")
	}
	for _, r := range rrW.udmReqs {
		if !r.hasHdr || r.apiRoot != want {
			return fmt.Errorf("%s %s carries %s=%q, want %q", r.method, r.uri, hdr, r.apiRoot, want)
		}
	}
	return nil
}

func rrAccept() error {
	if err := rrW.driveToEnd(); err != nil {
		return err
	}
	if !rrW.hasAccept() {
		return fmt.Errorf("the AMF did not send a REGISTRATION ACCEPT (reject cause %d, logs: %s)", rrW.hasReject(), rrW.logs.String())
	}
	return nil
}

func rrLocalZero() error {
	if n := len(rrW.lausf.snapshot()) + len(rrW.ludm.snapshot()); n != 0 {
		return fmt.Errorf("local AUSF/UDM mocks received %d request(s): %v %v", n, rrW.lausf.snapshot(), rrW.ludm.snapshot())
	}
	return nil
}

func rrVSEPPZero() error {
	if n := len(rrW.sepp.snapshot()); n != 0 {
		return fmt.Errorf("SEPP mock received %d request(s): %v", n, rrW.sepp.snapshot())
	}
	return nil
}

func rrLocalGotRegistration() error {
	if rrW.lausf.find("POST", rrAUSFPath, "") == nil ||
		rrW.lausf.find("PUT", rrAUSFPath+"/", "/5g-aka-confirmation") == nil {
		return fmt.Errorf("local AUSF mock did not receive authenticate + confirmation: %v", rrW.lausf.snapshot())
	}
	if rrW.ludm.find("PUT", "/nudm-uecm/", "/registrations/amf-3gpp-access") == nil ||
		rrW.ludm.find("GET", "/nudm-sdm/", "/am-data") == nil {
		return fmt.Errorf("local UDM mock did not receive UECM + SDM get: %v", rrW.ludm.snapshot())
	}
	return nil
}

func rrLocalGotAuthPOST() error {
	r := rrW.lausf.find("POST", rrAUSFPath, "")
	if r == nil || r.uri != rrAUSFPath {
		return fmt.Errorf("local AUSF mock did not receive POST %s (got %v)", rrAUSFPath, rrW.lausf.snapshot())
	}
	return nil
}

func rrNoHeaderAnywhere(hdr string) error {
	if hdr != roaming.TargetAPIRootHeader {
		return fmt.Errorf("unexpected header %q", hdr)
	}
	for _, s := range []*rrServer{rrW.sepp, rrW.lausf, rrW.ludm} {
		for _, r := range s.snapshot() {
			if r.hasHdr {
				return fmt.Errorf("%s received %s %s carrying %s=%q", s.role, r.method, r.uri, hdr, r.apiRoot)
			}
		}
	}
	return nil
}

func rrNoSBI() error {
	if err := rrVSEPPZero(); err != nil {
		return err
	}
	return rrLocalZero()
}

// rrBytesIdentical replays the same registration in a fresh world with no roaming
// block and compares every request the local AUSF and UDM mocks received.
func rrBytesIdentical() error {
	if err := rrW.driveToEnd(); err != nil {
		return err
	}
	ref := &rrWorld{mcc: rrW.mcc, mnc: rrW.mnc, snn: rrW.snn, logs: &nsaSyncBuf{},
		homes: rrW.homes, noRoamingBlock: true, seppEnabled: true, homePLMN: rrW.homePLMN}
	prev := rrW
	rrW = ref
	defer func() { rrW = prev }()
	if err := rrMocksRunning(); err != nil {
		return err
	}
	defer ref.closeAll()
	if err := ref.sendRegistration(); err != nil {
		return err
	}
	if err := ref.driveToEnd(); err != nil {
		return err
	}
	for _, p := range []struct {
		name     string
		got, ref *rrServer
	}{{"Nausf", prev.lausf, ref.lausf}, {"Nudm", prev.ludm, ref.ludm}} {
		a, b := p.got.snapshot(), p.ref.snapshot()
		if len(a) == 0 || len(a) != len(b) {
			return fmt.Errorf("%s: %d request(s) with roaming enabled vs %d with roaming disabled", p.name, len(a), len(b))
		}
		for i := range a {
			if a[i] != b[i] {
				return fmt.Errorf("%s request %d differs with roaming enabled:\n on  %+v\n off %+v", p.name, i, a[i], b[i])
			}
		}
	}
	return nil
}

// ---- Thens: UE context, NAS, logs -----------------------------------------

func rrHomeRouteOnContext(plmn string) error {
	w := rrW
	if err := w.sendRegistration(); err != nil {
		return err
	}
	rt := w.nw.ue.HomeRoute()
	if rt == nil {
		return errors.New("UE context holds no home route")
	}
	mcc, mnc, _ := rrSplitPLMN(plmn)
	var home *roaming.HomePLMN
	for i := range w.homes {
		if w.homes[i].PLMN == (roaming.PLMN{MCC: mcc, MNC: mnc}) {
			home = &w.homes[i]
		}
	}
	if home == nil {
		return fmt.Errorf("PLMN %s is not a configured home PLMN", plmn)
	}
	if rt.ViaSEPP == "" || rt.ViaSEPP != w.sepp.addr {
		return fmt.Errorf("home route ViaSEPP = %q, want the SEPP mock %q", rt.ViaSEPP, w.sepp.addr)
	}
	if rt.HomePLMN != home.PLMN || rt.AUSFAPIRoot != home.AUSFAPIRoot || rt.UDMAPIRoot != home.UDMAPIRoot {
		return fmt.Errorf("home route %+v does not match home PLMN %+v", *rt, *home)
	}
	return nil
}

func rrConfirmWithHeaderEqualHomeAUSF(hdr, _ string) error {
	if err := rrVSEPPGotConfirm(); err != nil {
		return err
	}
	return rrLastCarries(hdr, rrW.homes[0].AUSFAPIRoot)
}

func rrRejectCause(cause int) error {
	if err := rrW.driveToEnd(); err != nil {
		return err
	}
	if got := rrW.hasReject(); got != cause {
		return fmt.Errorf("REGISTRATION REJECT 5GMM cause = %d, want %d (DL = %x, logs: %s)", got, cause, rrW.dl(), rrW.logs.String())
	}
	return nil
}

func (w *rrWorld) records() []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(w.logs.String(), "\n") {
		var rec map[string]any
		if strings.TrimSpace(line) != "" && json.Unmarshal([]byte(line), &rec) == nil {
			out = append(out, rec)
		}
	}
	return out
}

// rrLogMatches finds a record with result == result and every key listed in
// wantKeys present and non-empty; extra equalities are checked by eq.
func rrLogMatches(result string, eq map[string]any, wantKeys ...string) error {
	var nearest []string
	for _, r := range rrW.records() {
		if r["result"] != result {
			continue
		}
		ok := true
		for k, v := range eq {
			if r[k] != v {
				ok = false
			}
		}
		if !ok {
			continue
		}
		var missing []string
		for _, k := range wantKeys {
			if s, has := r[k]; !has || s == "" || s == nil {
				missing = append(missing, k)
			}
		}
		if len(missing) == 0 {
			return nil
		}
		nearest = append(nearest, fmt.Sprintf("%v missing %v", r["msg"], missing))
	}
	return fmt.Errorf("no log record with result %q, %v and fields %v; closest: %v", result, eq, wantKeys, nearest)
}

func rrLogResult(result string, _ ...string) error {
	return rrLogMatches(result, nil, "spec_ref")
}

func rrLogCause(result string, cause int) error {
	return rrLogMatches(result, map[string]any{"cause": float64(cause)}, "home_plmn", "spec_ref")
}

func rrLogViaSEPP(result string) error {
	return rrLogMatches(result, map[string]any{"via_sepp": true})
}

func rrLogCauseHomePLMN(result string, cause int) error {
	return rrLogMatches(result, map[string]any{"cause": float64(cause)}, "home_plmn")
}

func (w *rrWorld) closeAll() {
	w.rp.cleanup()
	for _, s := range []*rrServer{w.sepp, w.lausf, w.ludm} {
		if s != nil && s.srv != nil {
			s.srv.Close()
		}
	}
	if w.nw != nil && w.nw.ue != nil {
		w.nw.ue.ClearRegProc() // stop T3560 so no timer outlives the scenario
	}
}

func initRoamingRegistrationSteps(sc *godog.ScenarioContext) {
	sc.After(func(ctx context.Context, _ *godog.Scenario, err error) (context.Context, error) {
		if rrW != nil {
			rrW.closeAll()
		}
		rrW = nil
		return ctx, nil
	})
	sc.Step(`^the AMF serves PLMN "([^"]*)" with serving network name "([^"]*)"$`, rrServes)
	sc.Step(`^a v?SEPP mock, a local AUSF mock and a local UDM mock are running$`, rrMocksRunning)
	sc.Step(`^the AMF is configured with roaming enabled, sepp_address pointing at the v?SEPP mock$`, rrRoamingEnabled)
	sc.Step(`^the AMF knows home PLMN "([^"]*)" with ausf_api_root "([^"]*)" and udm_api_root "([^"]*)"$`, rrKnowsHome)
	sc.Step(`^a gNB of PLMN "([^"]*)" is connected to the AMF$`, rrGNBConnected)

	sc.Step(`^the AMF configuration has no roaming block$`, rrNoRoamingBlock)
	sc.Step(`^a UE with a SUCI of home PLMN "([^"]*)" and the home network authorizes the serving network$`, rrUEAuthorized)
	sc.Step(`^a UE with a SUCI of home PLMN "([^"]*)"$`, rrUEWithSUCI)
	sc.Step(`^the v?SEPP mock relays the home AUSF answer (\d+) with ProblemDetails cause "([^"]*)"$`, rrRelayAUSF)
	sc.Step(`^the v?SEPP mock answers (504) with ProblemDetails cause "([^"]*)"$`, func(_ int, c string) error { return rrRelay504(c) })
	sc.Step(`^the v?SEPP mock relays the home UDM UECM answer (\d+) with ProblemDetails cause "([^"]*)"$`, rrRelayUECM)
	sc.Step(`^the v?SEPP mock is closed$`, rrCloseVSEPP)

	sc.Step(`^the UE sends a Registration Request of type "([^"]*)" via the ([0-9/]+) gNB$`, rrSendRegistration)
	sc.Step(`^the UE registers with initial Registration Request via the ([0-9/]+) gNB$`, rrSendRegistrationFull)
	sc.Step(`^the UE answers the Authentication Request with a valid RES\*$`, rrUEAnswersAuth)

	sc.Step(`^the v?SEPP mock receives the Nausf_UEAuthentication POST ue-authentications$`, rrVSEPPGotAuthPOST)
	sc.Step(`^that request carries header "([^"]*)" equal to "([^"]*)"$`, rrLastCarries)
	sc.Step(`^that request body has servingNetworkName "([^"]*)"$`, rrBodySNN)
	sc.Step(`^the v?SEPP mock receives the PUT 5g-aka-confirmation$`, rrVSEPPGotConfirm)
	sc.Step(`^the UDM UECM registration and the SDM get and subscribe requests reach the v?SEPP mock$`, rrUDMRequestsReachVSEPP)
	sc.Step(`^those requests carry header "([^"]*)" equal to "([^"]*)"$`, rrUDMRequestsCarry)
	sc.Step(`^the AMF sends a Registration Accept$`, rrAccept)
	sc.Step(`^the local AUSF mock and the local UDM mock received zero requests$`, rrLocalZero)

	sc.Step(`^the UE context in the AMF holds a home route with ViaSEPP set and the home AUSF and UDM apiRoots of PLMN "([^"]*)"$`, rrHomeRouteOnContext)
	sc.Step(`^the 5g-aka-confirmation is sent to the v?SEPP mock with header "([^"]*)" equal to the home AUSF apiRoot$`,
		func(h string) error { return rrConfirmWithHeaderEqualHomeAUSF(h, "") })

	sc.Step(`^the local AUSF mock and the local UDM mock receive the registration requests$`, rrLocalGotRegistration)
	sc.Step(`^the v?SEPP mock received zero requests$`, rrVSEPPZero)
	sc.Step(`^the Nausf and Nudm request bytes are identical to those sent with roaming disabled$`, rrBytesIdentical)

	sc.Step(`^the local AUSF mock receives the Nausf_UEAuthentication POST$`, rrLocalGotAuthPOST)
	sc.Step(`^no request carries header "([^"]*)"$`, rrNoHeaderAnywhere)

	sc.Step(`^the AMF sends a Registration Reject with 5GMM cause (\d+)$`, rrRejectCause)
	sc.Step(`^no SBI request leaves the AMF$`, rrNoSBI)
	sc.Step(`^the AMF logs result "([^"]*)" with cause (\d+), home_plmn and spec_ref$`, rrLogCause)
	sc.Step(`^the AMF logs result "([^"]*)" with cause (\d+) and home_plmn$`, rrLogCauseHomePLMN)
	sc.Step(`^the AMF logs result "([^"]*)" with via_sepp true$`, rrLogViaSEPP)
	sc.Step(`^the AMF logs result "([^"]*)" with spec_ref$`, func(r string) error { return rrLogResult(r) })
	initRoamingPartnersSteps(sc)
}
