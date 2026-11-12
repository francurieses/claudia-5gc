//go:build functional

// ics_failure_steps_test.go - in-process godog steps for the INITIAL CONTEXT
// SETUP FAILURE scenarios of initial_context_setup.feature (AMF-034, TS 38.413
// §8.3.1.3; TS 24.501 §5.5.1.2.8, §5.5.1.3.8 a)). A real AMF NGAP Server handles
// the encoded FAILURE PDU (DispatchNGAPForTest); the gNB is the fake SCTP
// transport seam, the SMF is a callback that records the released SM contexts.
package features_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cucumber/godog"
	"github.com/free5gc/aper"
	"github.com/ishidawataru/sctp"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	amfngap "github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	libngap "github.com/francurieses/claudia-5gc/shared/ngap"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

const icsFailGNBAddr = "10.0.0.7:38412"

// icsFailProtocolCauses maps the Protocol cause names used by the feature to the
// TS 38.413 §9.3.1.2 CauseProtocol values.
var icsFailProtocolCauses = map[string]aper.Enumerated{
	"transfer-syntax-error":                             0,
	"abstract-syntax-error-reject":                      1,
	"abstract-syntax-error-falsely-constructed-message": 5,
	"unspecified":                                       6,
}

type icsFailWorld struct {
	srv      *amfngap.Server
	mgr      *amfctx.Manager
	gnb      *amfngap.GNBContext
	ue       *amfctx.UEContext
	mu       sync.Mutex
	writes   [][]byte
	released []string
	relayed  []string
	logs     bytes.Buffer
	anCalls  int
}

var icsFailW = &icsFailWorld{}

func (w *icsFailWorld) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.logs.Write(p)
}

func (w *icsFailWorld) setup(supi string, kind amfctx.ICSKind, state amfctx.GMM5State, psis []uint8) error {
	*w = icsFailWorld{}
	w.mgr = amfctx.NewManager(amfctx.AMFIdentity{}, nil, nil, nil)
	w.srv = amfngap.NewServer("", w.mgr, nil, amfngap.AMFConfig{MCC: "001", MNC: "01"},
		slog.New(slog.NewJSONHandler(w, nil)))
	w.srv.SetPDUSessionSetupFailureHandler(func(_ context.Context, ref string) {
		w.mu.Lock()
		w.released = append(w.released, ref)
		w.mu.Unlock()
	})
	w.srv.SetPDUSessionSetupFailRelayHandler(func(_ context.Context, ref string, _ []byte) {
		w.mu.Lock()
		w.relayed = append(w.relayed, ref)
		w.mu.Unlock()
	})
	w.srv.SetANReleaseHandler(func(context.Context, *amfctx.UEContext) {})
	w.gnb = &amfngap.GNBContext{
		Name:    "gnb-ics-failure",
		UEs:     map[int64]*amfctx.UEContext{},
		IdleUEs: map[int64]*amfctx.UEContext{},
	}
	w.gnb.SetTransportForTest(icsFailGNBAddr, func(pdu []byte, _ *sctp.SndRcvInfo) (int, error) {
		w.mu.Lock()
		w.writes = append(w.writes, append([]byte(nil), pdu...))
		w.mu.Unlock()
		return len(pdu), nil
	})
	w.srv.AddGNBForTest(icsFailGNBAddr, w.gnb)
	w.srv.CompleteNGSetupForTest(w.gnb)

	ue := w.mgr.AllocateUEContext(7)
	w.mgr.SetSUPI(ue, supi)
	ue.GNBAddr = icsFailGNBAddr
	ue.CMState = amfctx.CMConnected
	ue.TransitionTo(state)
	for _, p := range psis {
		ue.PDUSessions[p] = &amfctx.PDUSession{PDUSessionID: p, SMFInstanceID: fmt.Sprintf("sm-ctx-%d", p)}
	}
	ue.SetPendingICS(kind)
	w.gnb.UEs[7] = ue
	w.ue = ue
	return nil
}

func buildICSFailure(amfID, ranID, protoCause int64, failed []int64) ([]byte, error) {
	ies := []ngapType.InitialContextSetupFailureIEs{
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitialContextSetupFailureIEsValue{
				Present:     ngapType.InitialContextSetupFailureIEsPresentAMFUENGAPID,
				AMFUENGAPID: &ngapType.AMFUENGAPID{Value: amfID},
			},
		},
		{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitialContextSetupFailureIEsValue{
				Present:     ngapType.InitialContextSetupFailureIEsPresentRANUENGAPID,
				RANUENGAPID: &ngapType.RANUENGAPID{Value: ranID},
			},
		},
	}
	if len(failed) > 0 { // spec IE order: ..., PDU Session Resource Failed to Setup List, Cause
		list := &ngapType.PDUSessionResourceFailedToSetupListCxtFail{}
		for _, p := range failed {
			list.List = append(list.List, ngapType.PDUSessionResourceFailedToSetupItemCxtFail{
				PDUSessionID: ngapType.PDUSessionID{Value: p},
				PDUSessionResourceSetupUnsuccessfulTransfer: []byte{0x00, 0x01},
			})
		}
		ies = append(ies, ngapType.InitialContextSetupFailureIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDPDUSessionResourceFailedToSetupListCxtFail},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitialContextSetupFailureIEsValue{
				Present: ngapType.InitialContextSetupFailureIEsPresentPDUSessionResourceFailedToSetupListCxtFail,
				PDUSessionResourceFailedToSetupListCxtFail: list,
			},
		})
	}
	ies = append(ies, ngapType.InitialContextSetupFailureIEs{
		Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDCause},
		Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
		Value: ngapType.InitialContextSetupFailureIEsValue{
			Present: ngapType.InitialContextSetupFailureIEsPresentCause,
			Cause: &ngapType.Cause{
				Present:  ngapType.CausePresentProtocol,
				Protocol: &ngapType.CauseProtocol{Value: aper.Enumerated(protoCause)},
			},
		},
	})
	return libngap.Encoder(ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentUnsuccessfulOutcome,
		UnsuccessfulOutcome: &ngapType.UnsuccessfulOutcome{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeInitialContextSetup},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.UnsuccessfulOutcomeValue{
				Present: ngapType.UnsuccessfulOutcomePresentInitialContextSetupFailure,
				InitialContextSetupFailure: &ngapType.InitialContextSetupFailure{
					ProtocolIEs: ngapType.ProtocolIEContainerInitialContextSetupFailureIEs{List: ies},
				},
			},
		},
	})
}

func (w *icsFailWorld) answer(cause string, failed []int64) error {
	pc, ok := icsFailProtocolCauses[cause]
	if !ok {
		return fmt.Errorf("unknown protocol cause %q", cause)
	}
	pdu, err := buildICSFailure(w.ue.AMFUENGAPId, 7, int64(pc), failed)
	if err != nil {
		return err
	}
	w.srv.DispatchNGAPForTest(context.Background(), w.gnb, pdu)
	w.srv.WaitUESerialForTest(w.ue.AMFUENGAPId)
	time.Sleep(100 * time.Millisecond) // async SMF relays
	return nil
}

func (w *icsFailWorld) releaseCommandCause(present int, want int64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, raw := range w.writes {
		pdu, err := libngap.Decoder(raw)
		if err != nil || pdu.InitiatingMessage == nil ||
			pdu.InitiatingMessage.ProcedureCode.Value != ngapType.ProcedureCodeUEContextRelease {
			continue
		}
		cmd := pdu.InitiatingMessage.Value.UEContextReleaseCommand
		for _, ie := range cmd.ProtocolIEs.List {
			if ie.Value.Cause != nil && ie.Value.Cause.Present == present &&
				ie.Value.Cause.RadioNetwork != nil && int64(ie.Value.Cause.RadioNetwork.Value) == want {
				return nil
			}
		}
	}
	return fmt.Errorf("no UE CONTEXT RELEASE COMMAND with radioNetwork cause %d among %d NGAP writes", want, len(w.writes))
}

func (w *icsFailWorld) releasedRefs() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := append([]string(nil), w.released...)
	sort.Strings(out)
	return out
}

func (w *icsFailWorld) relayedRefs() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := append([]string(nil), w.relayed...)
	sort.Strings(out)
	return out
}

func (w *icsFailWorld) logged(result, specRef string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	dec := json.NewDecoder(bytes.NewReader(w.logs.Bytes()))
	for {
		var rec map[string]any
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if rec["message_type"] == "InitialContextSetupFailure" && rec["result"] == result {
			if s, _ := rec["spec_ref"].(string); strings.Contains(s, specRef) {
				return nil
			}
		}
	}
	return fmt.Errorf("no InitialContextSetupFailure log with result %q and spec_ref containing %q", result, specRef)
}

func initICSFailureSteps(sc *godog.ScenarioContext) {
	w := icsFailW
	sc.Step(`^UE "([^"]+)" completed no registration yet and holds PDU sessions (\d+) and (\d+) after an initial registration ICS Request was sent$`,
		func(supi string, a, b int) error {
			return w.setup(supi, amfctx.ICSInitialRegistration, amfctx.GMMCommonProcedureInitiated, []uint8{uint8(a), uint8(b)})
		})
	sc.Step(`^UE "([^"]+)" is in 5GMM-REGISTERED state and holds PDU sessions (\d+) and (\d+) after a Service Request ICS Request was sent$`,
		func(supi string, a, b int) error {
			return w.setup(supi, amfctx.ICSServiceRequest, amfctx.GMMRegistered, []uint8{uint8(a), uint8(b)})
		})
	sc.Step(`^the gNB answers with INITIAL CONTEXT SETUP FAILURE with protocol cause "([^"]+)"$`,
		func(c string) error { return w.answer(c, nil) })
	sc.Step(`^the gNB answers with INITIAL CONTEXT SETUP FAILURE with protocol cause "([^"]+)" listing failed PDU session (\d+)$`,
		func(c string, psi int) error { return w.answer(c, []int64{int64(psi)}) })
	sc.Step(`^the UE transitions to 5GMM-DEREGISTERED and is flagged for removal$`, func() error {
		w.ue.Lock()
		defer w.ue.Unlock()
		if w.ue.State != amfctx.GMMDeregistered || !w.ue.PendingRemoval {
			return fmt.Errorf("state=%s pendingRemoval=%v", w.ue.State, w.ue.PendingRemoval)
		}
		return nil
	})
	sc.Step(`^the UE stays in 5GMM-REGISTERED state and is not flagged for removal$`, func() error {
		w.ue.Lock()
		defer w.ue.Unlock()
		if w.ue.State != amfctx.GMMRegistered || w.ue.PendingRemoval {
			return fmt.Errorf("state=%s pendingRemoval=%v", w.ue.State, w.ue.PendingRemoval)
		}
		return nil
	})
	sc.Step(`^the AMF sends a UE CONTEXT RELEASE COMMAND with radioNetwork cause "([^"]+)"$`, func(c string) error {
		if c != "release-due-to-5gc-generated-reason" {
			return fmt.Errorf("unsupported cause name %q", c)
		}
		return w.releaseCommandCause(ngapType.CausePresentRadioNetwork,
			int64(ngapType.CauseRadioNetworkPresentReleaseDueTo5gcGeneratedReason))
	})
	sc.Step(`^every PDU session of the UE is released at the SMF$`, func() error {
		if got := w.releasedRefs(); len(got) != 2 || got[0] != "sm-ctx-5" || got[1] != "sm-ctx-6" {
			return fmt.Errorf("SMF released %v, want sm-ctx-5 and sm-ctx-6", got)
		}
		return nil
	})
	// Registered UE: the failed PSI's Unsuccessful Transfer is relayed to the SMF
	// (PDU_RES_SETUP_FAIL, TS 38.413 §8.3.1.3); nothing is released by the AMF and
	// both PDU sessions stay in the UE context.
	sc.Step(`^the Unsuccessful Transfer of PDU session (\d+) is relayed to the SMF as PDU_RES_SETUP_FAIL and both sessions are kept$`, func(psi int) error {
		want := fmt.Sprintf("sm-ctx-%d", psi)
		if got := w.releasedRefs(); len(got) != 0 {
			return fmt.Errorf("AMF released %v at the SMF, want none (the SMF decides)", got)
		}
		if got := w.relayedRefs(); len(got) != 1 || got[0] != want {
			return fmt.Errorf("SMF got PDU_RES_SETUP_FAIL for %v, want only %s", got, want)
		}
		w.ue.Lock()
		defer w.ue.Unlock()
		if len(w.ue.PDUSessions) != 2 {
			return fmt.Errorf("UE holds %d PDU sessions, want 2", len(w.ue.PDUSessions))
		}
		return nil
	})
	sc.Step(`^the ICS failure is logged with result "([^"]+)" and spec_ref containing "([^"]+)"$`, w.logged)
}
