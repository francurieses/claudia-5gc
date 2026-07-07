//go:build functional

// service_request_steps_test.go — godog steps for service_request.feature
// (Service Request with user-plane re-activation, TS 23.502 §4.2.3).
//
// These scenarios require a full UERANSIM environment (make ueransim) and
// report as pending without E2E_TEST=1, mirroring pdu_session_modification.
//
// E2E validation recipe (docs/validation-commands.md §7):
//
//	make ueransim
//	GNB=UERANSIM-gnb-1-1-1
//	UEID=$(docker exec ueransim-gnb nr-cli $GNB --exec "ue-list" | grep -oE '[0-9]+' | head -1)
//	docker exec ueransim-gnb nr-cli $GNB --exec "ue-release $UEID"   # → CM-IDLE
//	docker exec ueransim-ue ping -I uesimtun0 -c 4 172.30.6.1        # → Service Request
//	docker logs amf | grep pdu_sessions_cxt_req                      # ICS carries N2SM
//	docker logs smf | grep "UP re-activation"                        # ACTIVATING branch
//
// The wire-level guarantees are unit-tested in:
//   - nf/amf/internal/ngap/initial_context_setup_test.go (CxtReq/CxtRes codec)
//   - nf/smf/internal/server/up_activation_test.go (ACTIVATING transfer rebuild)
//   - shared/nas + nf/amf/internal/procedures tai_list tests (IEI 0x54)
package features_test

import "github.com/cucumber/godog"

func regAcceptIncludesTAIList() error                  { return pendingIfNoE2E() }
func ueForcedCMIdleByANRelease() error                 { return pendingIfNoE2E() }
func ueSendsUplinkDataOnSession(_ string) error        { return pendingIfNoE2E() }
func ueSendsServiceRequestWithULStatus(_ string) error { return pendingIfNoE2E() }
func amfFetchesN2SMWithActivating() error              { return pendingIfNoE2E() }
func icsCarriesSessionInCxtReq(_ string) error         { return pendingIfNoE2E() }
func gnbReturnsDLTunnelInCxtRes() error                { return pendingIfNoE2E() }
func amfForwardsDLTunnelToSMF() error                  { return pendingIfNoE2E() }
func pingViaUETunnelSucceeds() error                   { return pendingIfNoE2E() }
func ueSendsSignallingOnlyServiceRequest() error       { return pendingIfNoE2E() }
func icsCarriesNoCxtReqList() error                    { return pendingIfNoE2E() }

func initServiceRequestSteps(sc *godog.ScenarioContext) {
	sc.Step(`^the Registration Accept sent to the UE includes a TAI list covering the serving TAC$`, regAcceptIncludesTAIList)
	sc.Step(`^the UE is forced to CM-IDLE by an AN Release$`, ueForcedCMIdleByANRelease)
	sc.Step(`^the UE sends uplink data on PDU session (\d+)$`, ueSendsUplinkDataOnSession)
	sc.Step(`^the UE sends a Service Request with PDU session (\d+) in the Uplink Data Status$`, ueSendsServiceRequestWithULStatus)
	sc.Step(`^the AMF fetches the N2SM Setup Request Transfer from the SMF with upCnxState ACTIVATING$`, amfFetchesN2SMWithActivating)
	sc.Step(`^the InitialContextSetupRequest carries PDU session (\d+) in the PDUSessionResourceSetupListCxtReq$`, icsCarriesSessionInCxtReq)
	sc.Step(`^the gNB returns the DL tunnel info in the InitialContextSetupResponse CxtRes list$`, gnbReturnsDLTunnelInCxtRes)
	sc.Step(`^the AMF forwards the DL tunnel info to the SMF to re-activate DL forwarding$`, amfForwardsDLTunnelToSMF)
	sc.Step(`^pinging the N6 gateway via the UE tunnel interface succeeds$`, pingViaUETunnelSucceeds)
	sc.Step(`^the UE sends a Service Request without an Uplink Data Status$`, ueSendsSignallingOnlyServiceRequest)
	sc.Step(`^the InitialContextSetupRequest carries no PDUSessionResourceSetupListCxtReq$`, icsCarriesNoCxtReqList)
}
