//go:build functional

// Package features_test - godog step definitions for the AUSF-hosted
// Nnssaaf_NSSAA slice authentication API (nssaa_slice_authentications.feature)
// and the unchanged legacy /nausf-nssaa relay.
// Run with: go test -tags=functional ./nf/ausf/tests/features/...
// Ref: TS 29.526 §5.2.2, TS 23.502 §4.2.9.2
package features_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cucumber/godog"

	ausfsrv "github.com/francurieses/claudia-5gc/nf/ausf/internal/server"
	"github.com/francurieses/claudia-5gc/shared/aka"
	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
)

const nssaaPath = "/nnssaaf-nssaa/v1/slice-authentications"

// nssaaWorld is the per-scenario state; every scenario gets a fresh AUSF.
type nssaaWorld struct {
	ts        *httptest.Server
	status    int
	header    http.Header
	body      map[string]any
	gpsi      string
	sst       int
	sd        string
	authCtx   string
	lastEAP   []byte
	challenge []byte // EAP message of the last 201, answered by confirm
}

func (w *nssaaWorld) reset() error {
	w.close()
	srv, err := ausfsrv.New(ausfsrv.Config{ServingNetworkName: snName}, &stubUDM{methods: map[string]string{}},
		aka.NewStore(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return fmt.Errorf("ausf new: %w", err)
	}
	w.ts = httptest.NewServer(srv.Handler())
	w.status, w.header, w.body, w.authCtx, w.lastEAP, w.challenge = 0, nil, nil, "", nil, nil
	return nil
}

func (w *nssaaWorld) close() {
	if w.ts != nil {
		w.ts.Close()
		w.ts = nil
	}
}

// do sends a JSON request and captures status, headers and body.
func (w *nssaaWorld) do(method, path string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, w.ts.URL+path, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.ts.Client().Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	w.status, w.header = resp.StatusCode, resp.Header
	rb, _ := io.ReadAll(resp.Body)
	w.body = nil
	_ = json.Unmarshal(rb, &w.body)
	w.lastEAP = nil
	if em, _ := w.body["eapMessage"].(string); em != "" {
		w.lastEAP, _ = base64.StdEncoding.DecodeString(em)
	}
	return nil
}

func b64(p []byte) string { return base64.StdEncoding.EncodeToString(p) }

func snssaiBody(sst int, sd string) map[string]any {
	return map[string]any{"sst": sst, "sd": sd}
}

// create POSTs a SliceAuthInfo; identity "" omits eapIdRsp, null sends JSON null.
func (w *nssaaWorld) create(gpsi string, sst int, sd string, eapIDRsp any) error {
	w.gpsi, w.sst, w.sd = gpsi, sst, sd
	b := map[string]any{"snssai": snssaiBody(sst, sd), "eapIdRsp": eapIDRsp}
	if gpsi != "" {
		b["gpsi"] = gpsi
	}
	if err := w.do(http.MethodPost, nssaaPath, b); err != nil {
		return err
	}
	if w.status == http.StatusCreated {
		w.authCtx, _ = w.body["authCtxId"].(string)
		w.challenge = w.lastEAP
	}
	return nil
}

func (w *nssaaWorld) createWithIdentity(gpsi string, sst int, sd, identity string) error {
	return w.create(gpsi, sst, sd, b64(eap.BuildIdentityResponse(1, identity)))
}

// confirm PUTs a SliceAuthConfirmationData answering the last EAP-Request.
func (w *nssaaWorld) confirm(ctxID string, sst int, sd string) error {
	id := byte(1)
	if len(w.challenge) >= 2 {
		id = w.challenge[1]
	}
	// EAP-Response (code 2) echoing the Request identifier, type MD5-Challenge (4).
	resp := []byte{eap.CodeResponse, id, 0, 6, 4, 1}
	return w.do(http.MethodPut, nssaaPath+"/"+ctxID, map[string]any{
		"gpsi": w.gpsi, "snssai": snssaiBody(sst, sd), "eapMessage": b64(resp),
	})
}

func (w *nssaaWorld) assertStatus(want int) error {
	if w.status != want {
		return fmt.Errorf("status: got %d want %d (body=%v)", w.status, want, w.body)
	}
	return nil
}

func (w *nssaaWorld) assertField(key, want string) error {
	if got, _ := w.body[key].(string); got != want {
		return fmt.Errorf("%s: got %q want %q (body=%v)", key, got, want, w.body)
	}
	return nil
}

func eapCodeByName(name string) (byte, error) {
	switch name {
	case "Request":
		return eap.CodeRequest, nil
	case "Success":
		return eap.CodeSuccess, nil
	case "Failure":
		return eap.CodeFailure, nil
	}
	return 0, fmt.Errorf("unknown EAP code name %q", name)
}

func TestNSSAASliceAuthenticationFeatures(t *testing.T) {
	w := &nssaaWorld{}
	suite := godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) {
			sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
				w.close()
				return ctx, nil
			})
			sc.Step(`^a clean AUSF with the Nnssaaf_NSSAA service is running$`, w.reset)
			sc.Step(`^the AMF creates a slice authentication for GPSI "([^"]*)" S-NSSAI sst (\d+) sd "([^"]*)" with EAP identity "([^"]*)"$`,
				w.createWithIdentity)
			sc.Step(`^the AMF creates a slice authentication for GPSI "([^"]*)" S-NSSAI sst (\d+) sd "([^"]*)" with a null eapIdRsp$`,
				func(gpsi string, sst int, sd string) error { return w.create(gpsi, sst, sd, nil) })
			sc.Step(`^the AMF creates a slice authentication without gpsi for S-NSSAI sst (\d+) sd "([^"]*)" with EAP identity "([^"]*)"$`,
				func(sst int, sd, identity string) error { return w.createWithIdentity("", sst, sd, identity) })
			sc.Step(`^the response status is (\d+)$`, w.assertStatus)
			sc.Step(`^the response has a Location header ending with the authCtxId$`, func() error {
				loc := w.header.Get("Location")
				if w.authCtx == "" || !strings.HasSuffix(loc, nssaaPath+"/"+w.authCtx) {
					return fmt.Errorf("Location %q does not end with %s/%s", loc, nssaaPath, w.authCtx)
				}
				return nil
			})
			sc.Step(`^the SliceAuthContext echoes GPSI "([^"]*)" and S-NSSAI sst (\d+) sd "([^"]*)"$`,
				func(gpsi string, sst int, sd string) error {
					sn, _ := w.body["snssai"].(map[string]any)
					if w.body["gpsi"] != gpsi || sn == nil || sn["sst"] != float64(sst) || sn["sd"] != sd {
						return fmt.Errorf("SliceAuthContext does not echo the request: %v", w.body)
					}
					return nil
				})
			sc.Step(`^the eapMessage carries EAP code "([^"]*)"$`, func(name string) error {
				want, err := eapCodeByName(name)
				if err != nil {
					return err
				}
				if len(w.lastEAP) < 4 || w.lastEAP[0] != want {
					return fmt.Errorf("eapMessage %x: want EAP code %d (%s)", w.lastEAP, want, name)
				}
				return nil
			})
			sc.Step(`^the problem cause is "([^"]*)"$`, func(v string) error { return w.assertField("cause", v) })
			sc.Step(`^the problem invalidParams names "([^"]*)"$`, func(param string) error {
				list, _ := w.body["invalidParams"].([]any)
				for _, it := range list {
					if m, ok := it.(map[string]any); ok && m["param"] == param {
						return nil
					}
				}
				return fmt.Errorf("invalidParams does not name %q: %v", param, w.body)
			})
			sc.Step(`^the authResult is "([^"]*)"$`, func(v string) error { return w.assertField("authResult", v) })
			sc.Step(`^the UE answers the EAP-Request and the AMF confirms the slice authentication$`, func() error {
				return w.confirm(w.authCtx, w.sst, w.sd)
			})
			sc.Step(`^the UE answers the EAP-Request and the AMF confirms the slice authentication using S-NSSAI sst (\d+) sd "([^"]*)"$`,
				func(sst int, sd string) error { return w.confirm(w.authCtx, sst, sd) })
			sc.Step(`^the AMF confirms the unknown authCtxId "([^"]*)" for GPSI "([^"]*)" S-NSSAI sst (\d+) sd "([^"]*)"$`,
				func(id, gpsi string, sst int, sd string) error {
					w.gpsi = gpsi
					return w.confirm(id, sst, sd)
				})
			sc.Step(`^the AMF relays EAP identity "([^"]*)" to the legacy NSSAA route for "([^"]*)"$`,
				func(identity, supi string) error {
					return w.do(http.MethodPost, "/nausf-nssaa/v1/"+supi+"/authenticate", map[string]any{
						"supi": supi, "snssai": snssaiBody(1, "000001"),
						"eapPayload": b64(eap.BuildIdentityResponse(1, identity)),
					})
				})
		},
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"nssaa_slice_authentications.feature"},
			TestingT: t,
			Strict:   true,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("NSSAA slice authentication feature scenarios failed")
	}
}
