//go:build functional

// godog steps for pdu_session_reestablishment.feature.
// Ref: TS 23.502 §4.3.2.2.1 step 1, TS 24.501 §6.4.1.2.
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cucumber/godog"
)

type reestWorld struct {
	s        *Server
	firstRef string
}

func (w *reestWorld) create(supi string, psi int) (string, error) {
	body, _ := json.Marshal(map[string]any{"supi": supi, "dnn": "internet", "pduSessionId": psi, "snssai": map[string]any{"sst": 1}})
	r := httptest.NewRequest(http.MethodPost, "/nsmf-pdusession/v1/sm-contexts", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	w.s.handleCreateSMContext(rec, r)
	var resp struct {
		SmContextRef string `json:"smContextRef"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return resp.SmContextRef, nil
}

func (w *reestWorld) active(supi string, psi int) error {
	ref, err := w.create(supi, psi)
	w.firstRef = ref
	w.s.sessionMu.Lock()
	w.s.sessions[ref].N4Stale = true // no PFCP socket in-process
	w.s.sessionMu.Unlock()
	return err
}

func (w *reestWorld) again(supi string, psi int) error {
	_, err := w.create(supi, psi)
	return err
}

func (w *reestWorld) count(n int, supi string, psi int) error {
	w.s.sessionMu.Lock()
	defer w.s.sessionMu.Unlock()
	c := 0
	for _, x := range w.s.sessions {
		if x.SUPI == supi && int(x.PDUSessionID) == psi {
			c++
		}
	}
	if c != n {
		return fmt.Errorf("assertion failed")
	}
	return nil
}

func (w *reestWorld) oldGone() error {
	w.s.sessionMu.Lock()
	defer w.s.sessionMu.Unlock()
	if w.s.sessions[w.firstRef] != nil {
		return fmt.Errorf("assertion failed")
	}
	return nil
}

func TestPduSessionReestablishmentFeature(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: func(ctx *godog.ScenarioContext) {
			w := &reestWorld{}
			ctx.Step(`^an SMF with an active session for "([^"]*)" PSI (\d+)$`, func(supi string, psi int) error {
				w.s = newActivationTestServer(t)
				return w.active(supi, psi)
			})
			ctx.Step(`^the AMF creates an SM context for "([^"]*)" PSI (\d+) again$`, w.again)
			ctx.Step(`^exactly (\d+) sessions? exists? for "([^"]*)" PSI (\d+)$`, w.count)
			ctx.Step(`^the old SM context no longer exists$`, w.oldGone)
		},
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"../../tests/features/pdu_session_reestablishment.feature"},
			TestingT: t,
		},
	}
	if suite.Run() != 0 {
		t.Fatal("godog scenarios failed")
	}
}
