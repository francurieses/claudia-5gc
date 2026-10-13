package ngap

import (
	"context"
	"time"

	"github.com/ishidawataru/sctp"
)

// Test seams for the gNB registry. The BDD suite lives in the external package
// nf/amf/tests/features and cannot reach unexported state, and a real SCTP
// association is deliberately avoided there (GNBContext.Conn is a concrete
// *sctp.SCTPConn). These thin wrappers drive exactly the code paths the NGAP
// connection handler uses. Production code does not call them.

// SetClockForTest replaces the registry clock.
func (s *Server) SetClockForTest(now func() time.Time) { s.now = now }

// AddGNBForTest registers a gNB under the given remote address key in SCTP_UP
// state, as handleGNBConn does when an association comes up.
func (s *Server) AddGNBForTest(remoteAddr string, g *GNBContext) {
	g.ConnectedAt = s.clock()
	g.State = GNBStateSCTPUp
	s.mu.Lock()
	if s.gnbs == nil {
		s.gnbs = make(map[string]*GNBContext)
	}
	s.gnbs[remoteAddr] = g
	s.mu.Unlock()
}

// CompleteNGSetupForTest marks the gNB NG_READY, as handleNGSetup does after a
// successful NG Setup Response.
func (s *Server) CompleteNGSetupForTest(g *GNBContext) { s.markGNBReady(g) }

// DisconnectGNBForTest removes the gNB and records it in the history, as the
// handleGNBConn defer does when the association ends.
func (s *Server) DisconnectGNBForTest(remoteAddr, reason string) {
	s.mu.Lock()
	if g, ok := s.gnbs[remoteAddr]; ok {
		delete(s.gnbs, remoteAddr)
		s.recordGNBDisconnectLocked(g, remoteAddr, reason)
	}
	s.mu.Unlock()
}

// ObserveNGResetForTest records an NG Reset on the gNB.
func (s *Server) ObserveNGResetForTest(g *GNBContext) { s.observeNGReset(g) }

// NewGlobalGNBForTest builds a Global RAN Node of type gNB.
func NewGlobalGNBForTest(mcc, mnc string, id uint32, bitLen uint8) GlobalRANNode {
	return GlobalRANNode{Type: RANNodeTypeGNB, MCC: mcc, MNC: mnc, GNBID: id, GNBIDBitLen: bitLen}
}

// SetTransportForTest installs a fake SCTP transport on the gNB: write receives
// every NGAP PDU together with the SndRcvInfo the AMF would hand to SCTPWrite
// (so a test can assert PPID 60), and remoteAddr is the association key stored in
// UEContext.GNBAddr. Production code does not call it.
func (g *GNBContext) SetTransportForTest(remoteAddr string, write func(pdu []byte, info *sctp.SndRcvInfo) (int, error)) {
	g.testAddr = remoteAddr
	g.sctpWrite = write
}

// HandlePathSwitchRequestForTest runs the Path Switch Request handler on a decoded request
// and waits until the UE's serial task (the synchronous SMF leg, Ack/Failure send and
// re-bind) has finished, so a test can assert right after the call.
func (s *Server) HandlePathSwitchRequestForTest(ctx context.Context, target *GNBContext, req *PathSwitchRequestMsg) {
	s.StartPathSwitchRequestForTest(ctx, target, req)
	s.WaitUESerialForTest(req.SourceAMFUENGAPId)
}

// StartPathSwitchRequestForTest runs only the inline part of the Path Switch Request
// handler, exactly as the SCTP read loop does; the SMF leg continues on the UE's serial
// queue (use WaitUESerialForTest to wait for it). It lets a test hold an SMF answer and
// observe that the handler call itself did not block.
func (s *Server) StartPathSwitchRequestForTest(ctx context.Context, target *GNBContext, req *PathSwitchRequestMsg) {
	s.handlePathSwitchRequest(ctx, target, &Message{Value: req})
}

// WaitUESerialForTest blocks until every task already queued on the serial queue of the
// UE with the given AMF UE NGAP ID has run (no-op for an unknown UE). It gives up after
// 30 s so a wedged test fails instead of hanging; it reports whether the queue drained.
func (s *Server) WaitUESerialForTest(amfUENGAPId int64) bool {
	ue, ok := s.mgr.GetByNGAPId(amfUENGAPId)
	if !ok {
		return true
	}
	done := make(chan struct{})
	ue.EnqueueSerial(func() { close(done) })
	select {
	case <-done:
		return true
	case <-time.After(30 * time.Second):
		return false
	}
}

// SetSMFHOUpdateTimeoutForTest overrides the per-PDU-session SMF wait of the handover
// SMF leg (default smfHOUpdateTimeout). d <= 0 restores the default.
func (s *Server) SetSMFHOUpdateTimeoutForTest(d time.Duration) { s.smfHOTimeout = d }

// HasPendingN2HandoverForTest reports whether an N2 handover is pending for the AMF UE
// NGAP ID (created on HandoverRequired, dropped on HandoverNotify or SMF-leg failure).
func (s *Server) HasPendingN2HandoverForTest(amfUENGAPId int64) bool {
	s.pendingN2HOMu.Lock()
	defer s.pendingN2HOMu.Unlock()
	_, ok := s.pendingN2HO[amfUENGAPId]
	return ok
}

// HandleHandoverRequiredForTest runs the Handover Required handler on a decoded message and
// waits for the UE's serial task (PREPARING SMF leg + HANDOVER REQUEST / PREPARATION FAILURE).
func (s *Server) HandleHandoverRequiredForTest(ctx context.Context, source *GNBContext, req *HandoverRequiredMsg) {
	s.StartHandoverRequiredForTest(ctx, source, req)
	s.WaitUESerialForTest(req.AMFUENGAPId)
}

// StartHandoverRequiredForTest runs only the inline part of the Handover Required handler,
// exactly as the SCTP read loop does; the PREPARING SMF leg continues on the UE's serial
// queue (use WaitUESerialForTest to wait for it).
func (s *Server) StartHandoverRequiredForTest(ctx context.Context, source *GNBContext, req *HandoverRequiredMsg) {
	s.handleHandoverRequired(ctx, source, &Message{Value: req})
}

// HandleHandoverNotifyForTest runs the Handover Notify handler on a decoded message and waits
// for the in-flight Handover Complete SMF calls it started.
func (s *Server) HandleHandoverNotifyForTest(ctx context.Context, target *GNBContext, notify *HandoverNotifyMsg) {
	s.handleHandoverNotify(ctx, target, &Message{Value: notify})
	s.hoCompleteWG.Wait()
}

// HandleHandoverRequestAcknowledgeForTest runs the Handover Request Acknowledge handler
// and waits for the UE's serial task (SMF leg + HANDOVER COMMAND / PREPARATION FAILURE).
func (s *Server) HandleHandoverRequestAcknowledgeForTest(ctx context.Context, target *GNBContext, ack *HandoverRequestAckMsg) {
	s.StartHandoverRequestAcknowledgeForTest(ctx, target, ack)
	s.WaitUESerialForTest(ack.AMFUENGAPId)
}

// StartHandoverRequestAcknowledgeForTest runs only the inline part of the Handover
// Request Acknowledge handler; the SMF leg continues on the UE's serial queue.
func (s *Server) StartHandoverRequestAcknowledgeForTest(ctx context.Context, target *GNBContext, ack *HandoverRequestAckMsg) {
	s.handleHandoverRequestAcknowledge(ctx, target, &Message{Value: ack})
}

// HandleUplinkNASTransportForTest dispatches an UplinkNASTransport for the UE identified by
// msg.AMFUENGAPId on gnb exactly as the SCTP read loop's dispatch does for ProcCode 46
// (handleUplinkNASTransport on the decoded message). Build msg as
// &UplinkNASTransport{AMFUENGAPId: ..., RANUENGAPId: ..., NASPdu: nasBytes}. It returns
// when the handler returns; NAS work that blocks (SBI calls) runs on the UE's serial
// queue, so the call itself must not wait for another UE's pending SMF leg.
func (s *Server) HandleUplinkNASTransportForTest(ctx context.Context, gnb *GNBContext, msg *UplinkNASTransport) {
	s.handleUplinkNASTransport(ctx, gnb, &Message{ProcedureCode: ProcUplinkNASTransport, Value: msg})
}

// DispatchNGAPForTest feeds a gNB-originated NGAP PDU through the server's
// dispatcher, as if it had arrived on the gNB's SCTP association.
func (s *Server) DispatchNGAPForTest(ctx context.Context, gnb *GNBContext, pdu []byte) {
	s.dispatch(ctx, gnb, pdu)
}
