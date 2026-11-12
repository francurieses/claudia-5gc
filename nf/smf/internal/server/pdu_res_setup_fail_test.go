package server

import (
	"encoding/base64"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

func resSetupFailPost(t *testing.T, s *Server, ref string, raw []byte) int {
	t.Helper()
	return hoPost(s, ref, map[string]interface{}{"n2SmInfoType": "PDU_RES_SETUP_FAIL",
		"n2SmInfo": base64.StdEncoding.EncodeToString(raw)}).Code
}

func TestPduResSetupFail(t *testing.T) {
	cause := ngapCause(ngapType.CausePresentRadioNetwork, ngapType.CauseRadioNetworkPresentRadioResourcesNotAvailable)
	good := func(t *testing.T) []byte {
		return hoMarshal(t, ngapType.PDUSessionResourceSetupUnsuccessfulTransfer{Cause: cause})
	}
	t.Run("deactivates once", func(t *testing.T) {
		s, sess, upf := hoRespFixture(t)
		if c := resSetupFailPost(t, s, hoTestRef, good(t)); c != 204 {
			t.Fatalf("code = %d", c)
		}
		s.WaitHandoverTasks()
		if len(upf.requests()) != 1 || hoState(s, sess) != "IDLE" {
			t.Fatalf("pfcp=%d state=%q", len(upf.requests()), hoState(s, sess))
		}
	})
	t.Run("already inactive no N4", func(t *testing.T) {
		s, sess, upf := hoRespFixture(t)
		sess.State = "IDLE"
		if c := resSetupFailPost(t, s, hoTestRef, good(t)); c != 204 {
			t.Fatalf("code = %d", c)
		}
		s.WaitHandoverTasks()
		if len(upf.requests()) != 0 {
			t.Fatal("N4 sent for inactive session")
		}
	})
	t.Run("unknown ref 404", func(t *testing.T) {
		s, _, _ := hoRespFixture(t)
		if c := resSetupFailPost(t, s, "nope", good(t)); c != 404 {
			t.Fatalf("code = %d", c)
		}
	})
	t.Run("releasing 409 no N4", func(t *testing.T) {
		s, sess, upf := hoRespFixture(t)
		sess.State = sessionStateReleasing
		if c := resSetupFailPost(t, s, hoTestRef, good(t)); c != 409 {
			t.Fatalf("code = %d", c)
		}
		s.WaitHandoverTasks()
		if len(upf.requests()) != 0 {
			t.Fatal("N4 sent for releasing session")
		}
	})
	t.Run("garbage transfer still deactivates", func(t *testing.T) {
		s, sess, upf := hoRespFixture(t)
		if c := resSetupFailPost(t, s, hoTestRef, []byte{0xff, 0xff, 0xff}); c != 204 {
			t.Fatalf("code = %d", c)
		}
		s.WaitHandoverTasks()
		if len(upf.requests()) != 1 || hoState(s, sess) != "IDLE" {
			t.Fatalf("pfcp=%d state=%q", len(upf.requests()), hoState(s, sess))
		}
	})
}
