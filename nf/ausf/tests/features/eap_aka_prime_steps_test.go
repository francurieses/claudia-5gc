//go:build functional

// Package features contains godog BDD step definitions for AUSF EAP-AKA'.
// Run with: go test -tags=functional ./nf/ausf/tests/features/...
// Ref: TS 33.501 §6.1.3.1, RFC 5448
package features_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cucumber/godog"

	ausfsrv "github.com/francurieses/claudia-5gc/nf/ausf/internal/server"
	"github.com/francurieses/claudia-5gc/shared/aka"
	"github.com/francurieses/claudia-5gc/shared/crypto/eapaka"
)

const snName = "5G:mnc001.mcc001.3gppnetwork.org"

var heavInput = aka.HEAVInput{
	K:   [16]byte{0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc},
	OPc: [16]byte{0xe8, 0xed, 0x28, 0x9d, 0xeb, 0xa9, 0x52, 0xe4, 0x28, 0x3b, 0x54, 0xe8, 0x8e, 0x61, 0x83, 0xca},
	AMF: [2]byte{0x80, 0x00},
	SQN: [6]byte{0, 0, 0, 0, 0, 0x21},
}

// stubUDM returns an EAP-AKA' or 5G-AKA AV per the provisioned method.
type stubUDM struct {
	methods map[string]string
	lastAV  *aka.EAPAKAPrimeAV
}

func (s *stubUDM) GenerateAuthData(_ context.Context, supi string, _ *ausfsrv.UDMAuthDataRequest) (*ausfsrv.UDMAuthDataResponse, error) {
	if s.methods[supi] == "EAP_AKA_PRIME" {
		av, err := aka.GenerateEAPAKAPrime(heavInput, snName)
		if err != nil {
			return nil, err
		}
		s.lastAV = av
		return &ausfsrv.UDMAuthDataResponse{
			AuthType: "EAP_AKA_PRIME",
			Rand:     hex.EncodeToString(av.RAND[:]),
			Autn:     hex.EncodeToString(av.AUTN[:]),
			Xres:     hex.EncodeToString(av.XRES[:]),
			CkPrime:  hex.EncodeToString(av.CKPrime[:]),
			IkPrime:  hex.EncodeToString(av.IKPrime[:]),
			Supi:     supi,
		}, nil
	}
	heav, err := aka.GenerateFull(heavInput, snName)
	if err != nil {
		return nil, err
	}
	return &ausfsrv.UDMAuthDataResponse{
		AuthType: "5G_AKA",
		Rand:     hex.EncodeToString(heav.RAND[:]),
		Autn:     hex.EncodeToString(heav.AUTN[:]),
		XresStar: hex.EncodeToString(heav.XRESStar),
		Kausf:    hex.EncodeToString(heav.KAUSF),
		Supi:     supi,
	}, nil
}

type ausfWorld struct {
	ts     *httptest.Server
	udm    *stubUDM
	supi   string
	status int
	body   map[string]any
	href   string
	eapID  byte
}

func (w *ausfWorld) reset() {
	w.udm = &stubUDM{methods: map[string]string{}}
	srv, err := ausfsrv.New(ausfsrv.Config{ServingNetworkName: snName}, w.udm, aka.NewStore(),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		panic(err)
	}
	if w.ts != nil {
		w.ts.Close()
	}
	w.ts = httptest.NewServer(srv.Handler())
	w.status, w.body, w.href, w.eapID, w.supi = 0, nil, "", 0, ""
}

func (w *ausfWorld) provision(supi, method string) error {
	w.udm.methods[supi] = method
	return nil
}

func (w *ausfWorld) initAuth(supi string) error {
	w.supi = supi
	body, _ := json.Marshal(map[string]string{"supiOrSuci": supi, "servingNetworkName": snName})
	resp, err := http.Post(w.ts.URL+"/nausf-auth/v1/ue-authentications", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	w.status = resp.StatusCode
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &w.body)
	if auth, _ := w.body["5gAuthData"].(map[string]any); auth != nil {
		if ep, _ := auth["eapPayload"].(string); ep != "" {
			if chal, err := base64.StdEncoding.DecodeString(ep); err == nil && len(chal) >= 2 {
				w.eapID = chal[1]
			}
		}
	}
	if links, _ := w.body["_links"].(map[string]any); links != nil {
		if es, _ := links["eap-session"].(map[string]any); es != nil {
			w.href, _ = es["href"].(string)
		}
	}
	return nil
}

func (w *ausfWorld) putEAP(href string, eap []byte) error {
	body, _ := json.Marshal(map[string]string{"eapPayload": base64.StdEncoding.EncodeToString(eap)})
	req, _ := http.NewRequest(http.MethodPut, w.ts.URL+href, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	w.status = resp.StatusCode
	raw, _ := io.ReadAll(resp.Body)
	w.body = map[string]any{}
	_ = json.Unmarshal(raw, &w.body)
	return nil
}

func (w *ausfWorld) submitCorrectResponse() error {
	keys := eapaka.DeriveKeys(w.udm.lastAV.CKPrime, w.udm.lastAV.IKPrime, w.supi)
	return w.putEAP(w.href, eapaka.BuildResponse(w.eapID, w.udm.lastAV.XRES[:], keys.KAut))
}

func (w *ausfWorld) submitBadMAC() error {
	return w.putEAP(w.href, eapaka.BuildResponse(w.eapID, w.udm.lastAV.XRES[:], make([]byte, 32)))
}

func (w *ausfWorld) submitBadRES() error {
	keys := eapaka.DeriveKeys(w.udm.lastAV.CKPrime, w.udm.lastAV.IKPrime, w.supi)
	return w.putEAP(w.href, eapaka.BuildResponse(w.eapID, make([]byte, 8), keys.KAut))
}

func (w *ausfWorld) assertStatus(want int) error {
	if w.status != want {
		return fmt.Errorf("status: got %d want %d (body=%v)", w.status, want, w.body)
	}
	return nil
}

func (w *ausfWorld) assertBodyField(key, want string) error {
	if got, _ := w.body[key].(string); got != want {
		return fmt.Errorf("%s: got %q want %q", key, got, want)
	}
	return nil
}

func (w *ausfWorld) assertEAPCode(code byte, label string) error {
	auth, _ := w.body["5gAuthData"].(map[string]any)
	ep := ""
	if auth != nil {
		ep, _ = auth["eapPayload"].(string)
	}
	if ep == "" {
		ep, _ = w.body["eapPayload"].(string)
	}
	pkt, err := base64.StdEncoding.DecodeString(ep)
	if err != nil || len(pkt) < 1 {
		return fmt.Errorf("no decodable EAP payload for %s", label)
	}
	if pkt[0] != code {
		return fmt.Errorf("%s: EAP code got %d want %d", label, pkt[0], code)
	}
	return nil
}

func TestEAPAKAPrimeFeatures(t *testing.T) {
	w := &ausfWorld{}
	suite := godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) {
			sc.Step(`^a clean AUSF instance is running$`, func() error { w.reset(); return nil })
			sc.Step(`^the UDM is provisioned for subscriber "([^"]*)" with method "([^"]*)"$`, w.provision)
			sc.Step(`^AMF initiates authentication for "([^"]*)"$`, w.initAuth)
			sc.Step(`^the response status is (\d+)$`, func(c int) error { return w.assertStatus(c) })
			sc.Step(`^the response authType is "([^"]*)"$`, func(v string) error { return w.assertBodyField("authType", v) })
			sc.Step(`^the response contains an EAP-Request AKA-Challenge payload$`, func() error { return w.assertEAPCode(eapaka.CodeRequest, "challenge") })
			sc.Step(`^the response has an eap-session link$`, func() error {
				if w.href == "" {
					return fmt.Errorf("missing eap-session link")
				}
				return nil
			})
			sc.Step(`^the UE computes a correct EAP-Response and AMF submits it$`, w.submitCorrectResponse)
			sc.Step(`^the eap-session response status is (\d+)$`, func(c int) error { return w.assertStatus(c) })
			sc.Step(`^the authResult is "([^"]*)"$`, func(v string) error { return w.assertBodyField("authResult", v) })
			sc.Step(`^the response contains a non-empty kSeaf$`, func() error {
				if ks, _ := w.body["kSeaf"].(string); len(ks) != 64 {
					return fmt.Errorf("kSeaf invalid: %q", ks)
				}
				return nil
			})
			sc.Step(`^the response contains the EAP-Success payload$`, func() error { return w.assertEAPCode(eapaka.CodeSuccess, "success") })
			sc.Step(`^the UE submits an EAP-Response with a corrupted AT_MAC$`, w.submitBadMAC)
			sc.Step(`^no kSeaf is returned$`, func() error {
				if _, ok := w.body["kSeaf"]; ok {
					return fmt.Errorf("kSeaf unexpectedly present")
				}
				return nil
			})
			sc.Step(`^the UE submits an EAP-Response with an incorrect RES$`, w.submitBadRES)
			sc.Step(`^AMF submits an EAP-Response for auth context "([^"]*)"$`, func(id string) error {
				return w.putEAP("/nausf-auth/v1/ue-authentications/"+id+"/eap-session", eapaka.BuildSuccess(1))
			})
			sc.Step(`^the cause is "([^"]*)"$`, func(v string) error { return w.assertBodyField("cause", v) })
		},
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"."},
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("EAP-AKA' feature scenarios failed")
	}
}
