// Package server: this file implements PFCP node-level supervision of the UPF
// on N4 (SMF-004): SMF-initiated PFCP Association Setup, periodic PFCP
// Heartbeat, UPF restart / failure detection and recovery by RELEASE of the
// affected PDU sessions (PFCP session restoration is deliberately NOT done,
// human decision 2026-10-05).
//
// Refs: TS 29.244 §6.2.2 (Heartbeat), §6.2.6.2 (Association Setup, CP function
// initiated), §6.4 (reliable delivery, T1/N1), §7.4.2 / §7.4.4 (messages),
// §8.2.65 (Recovery Time Stamp); TS 23.007 §19A (PFCP based restart
// procedures); TS 23.527 §4.2 (N4 failure and restart detection), §4.3
// (restoration); TS 23.502 §4.3.4.2 (SMF-requested PDU session release).
//
// Design: docs/procedures/PfcpNodeLevelRecovery.md.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"

	"github.com/francurieses/claudia-5gc/nf/smf/internal/config"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

// Default PFCP supervision timers. 3GPP gives no values: TS 29.244 §6.4 only
// says T1 and N1 are configurable and the Heartbeat period is an operator
// choice. The defaults aim to detect a UPF restart within a few seconds so the
// restart E2E check sees the released session.
const (
	// defaultPFCPHeartbeatInterval is the Heartbeat Request period (TS 29.244 §6.2.2).
	defaultPFCPHeartbeatInterval = 2 * time.Second
	// defaultPFCPT1 is the request retransmission timer T1 (TS 29.244 §6.4).
	defaultPFCPT1 = 3 * time.Second
	// defaultPFCPN1 is the maximum number of retransmissions N1 (TS 29.244 §6.4).
	defaultPFCPN1 = 3
	// defaultPFCPAssocRetryInitial is the first Association Setup back-off
	// (implementation choice, TS 29.244 §6.2.6.2 defines no retry timing).
	defaultPFCPAssocRetryInitial = 1 * time.Second
	// defaultPFCPAssocRetryMax caps the Association Setup back-off.
	defaultPFCPAssocRetryMax = 5 * time.Second
)

const (
	// amfReleaseTimeout bounds one AMF management release call.
	amfReleaseTimeout = 5 * time.Second
	// amfReleaseConcurrency bounds the AMF release calls in flight so a large
	// session table cannot flood the AMF management API.
	amfReleaseConcurrency = 4
	// pfcpNodeMaxDatagram is the receive buffer for node-level PFCP responses.
	pfcpNodeMaxDatagram = 2048
	// pfcpSeqMax is the largest PFCP Sequence Number: the field is 3 octets
	// (TS 29.244 §7.2.2).
	pfcpSeqMax = 0xFFFFFF
	// defaultPFCPReleaseGuard bounds how long a session stays RELEASING after the
	// AMF accepted the release request. Implementation choice (no 3GPP value):
	// longer than the AMF-side PDU Session Release handling (T3592 retransmissions,
	// TS 24.501 §10.3) so the normal ReleaseSMContext path wins; afterwards the SMF
	// frees the context itself (TS 23.502 §4.3.4.2).
	defaultPFCPReleaseGuard = 30 * time.Second
)

// PFCP association states of the supervised UPF peer (docs/procedures/
// PfcpNodeLevelRecovery.md "state machine").
const (
	// assocSetupPending: no PFCP association; Association Setup being (re)tried.
	assocSetupPending = "SETUP_PENDING"
	// assocAssociated: Association Setup accepted; Heartbeats running.
	assocAssociated = "ASSOCIATED"
	// assocRecovering: transient state after a restart/failure detection.
	assocRecovering = "RECOVERING"
)

// sessionStateReleasing marks a session being released after a UPF restart or
// failure. It is the idempotency guard of the release worker.
const sessionStateReleasing = "RELEASING"

// Recovery causes (log/metric values).
const (
	causePeerRestart       = "PEER_RESTART"
	causePeerNotResponding = "PEER_NOT_RESPONDING"
	causeRTSMissing        = "RTS_MISSING"
	causeAMFReleaseFailed  = "AMF_RELEASE_FAILED"
)

// Procedure names and spec references used in logs and metrics.
const (
	procAssocSetup = "PfcpAssociationSetup"
	procHeartbeat  = "PfcpHeartbeat"
	procRecovery   = "PfcpNodeLevelRecovery"

	specAssocSetup = "TS 29.244 §6.2.6.2"
	specHeartbeat  = "TS 29.244 §6.2.2"
	specDetect     = "TS 23.527 §4.2"
	specRestore    = "TS 23.527 §4.3"
	// specRestorePeerRestart / specRestorePeerFailure are the restoration
	// clauses logged as restoration_spec_ref per detection cause.
	specRestorePeerRestart = "TS 23.527 §4.3.2"
	specRestorePeerFailure = "TS 23.527 §4.3.3"
	// specHeartbeatLost cites the T1/N1 exhaustion and the N4 failure detection.
	specHeartbeatLost = "TS 29.244 §6.4; TS 23.527 §4.2"
	specAMFRelease    = "TS 23.502 §4.3.4.2"
)

// errPFCPTimeout is returned by pfcpTransact when no matching response arrived
// after the initial transmission and N1 retransmissions (TS 29.244 §6.4).
var errPFCPTimeout = errors.New("smf: pfcp: no response after N1 retransmissions")

// pfcpNodeTimers groups the supervision timers. Unexported so that functional
// tests (package server) can shrink them to sub-second values.
type pfcpNodeTimers struct {
	heartbeatInterval time.Duration
	t1                time.Duration
	n1                int
	assocRetryInitial time.Duration
	assocRetryMax     time.Duration
	// releaseGuard is the RELEASING-session safety timeout; <= 0 disables it.
	releaseGuard time.Duration
}

// pfcpTimersFromConfig applies the defaults for zero/absent config values.
func pfcpTimersFromConfig(n4 config.N4Config) pfcpNodeTimers {
	t := pfcpNodeTimers{
		heartbeatInterval: defaultPFCPHeartbeatInterval,
		t1:                defaultPFCPT1,
		n1:                defaultPFCPN1,
		assocRetryInitial: defaultPFCPAssocRetryInitial,
		assocRetryMax:     defaultPFCPAssocRetryMax,
		releaseGuard:      defaultPFCPReleaseGuard,
	}
	if n4.HeartbeatIntervalSeconds > 0 {
		t.heartbeatInterval = time.Duration(n4.HeartbeatIntervalSeconds) * time.Second
	}
	if n4.T1Seconds > 0 {
		t.t1 = time.Duration(n4.T1Seconds) * time.Second
	}
	if n4.N1Retransmissions > 0 {
		t.n1 = n4.N1Retransmissions
	}
	if n4.AssociationRetryInitialSeconds > 0 {
		t.assocRetryInitial = time.Duration(n4.AssociationRetryInitialSeconds) * time.Second
	}
	if n4.AssociationRetryMaxSeconds > 0 {
		t.assocRetryMax = time.Duration(n4.AssociationRetryMaxSeconds) * time.Second
	}
	if t.assocRetryMax < t.assocRetryInitial {
		t.assocRetryMax = t.assocRetryInitial
	}
	return t
}

// pfcpAssociation is the supervised-UPF association state, guarded by mu.
type pfcpAssociation struct {
	mu               sync.Mutex
	state            string
	peerNodeID       string
	remoteRTS        time.Time // zero = unknown (baseline not yet learned)
	associatedAt     time.Time
	missingRTSWarned bool
}

// PFCPAssociationStatus is a read-only snapshot of the association state.
type PFCPAssociationStatus struct {
	State        string    // SETUP_PENDING | ASSOCIATED | RECOVERING
	PeerNodeID   string    // Node ID returned in the Association Setup Response
	RemoteRTS    time.Time // UPF Recovery Time Stamp baseline (zero = unknown)
	AssociatedAt time.Time
}

// PFCPAssociation returns a snapshot of the UPF association state.
func (s *Server) PFCPAssociation() PFCPAssociationStatus {
	s.assoc.mu.Lock()
	defer s.assoc.mu.Unlock()
	return PFCPAssociationStatus{
		State:        s.assoc.state,
		PeerNodeID:   s.assoc.peerNodeID,
		RemoteRTS:    s.assoc.remoteRTS,
		AssociatedAt: s.assoc.associatedAt,
	}
}

// nextPFCPSeq returns the next PFCP Sequence Number, always in 1..0xFFFFFF:
// the header field is 3 octets (TS 29.244 §7.2.2), so the shared 32-bit counter
// is wrapped (..., 0xFFFFFF, 1, 2, ...); 0 is never returned.
func (s *Server) nextPFCPSeq() uint32 {
	return (s.pfcpSeq.Add(1)-1)%pfcpSeqMax + 1
}

// RecoveryTimeStamp returns the SMF local Recovery Time Stamp (seconds resolution).
func (s *Server) RecoveryTimeStamp() time.Time { return s.recoveryTS }

// WaitPFCPRelease blocks until all in-flight PFCP-recovery release workers have
// finished (used by tests and graceful shutdown).
func (s *Server) WaitPFCPRelease() { s.releaseWG.Wait() }

// rtsOf normalises a Recovery Time Stamp to its wire resolution (whole
// seconds, TS 29.244 §8.2.65) so comparisons never see sub-second noise.
func rtsOf(t time.Time) time.Time { return t.UTC().Truncate(time.Second) }

func fmtRTS(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// RunPFCPNodeSupervisor supervises the configured UPF peer until ctx is
// cancelled: Association Setup with bounded exponential back-off, then
// Heartbeats; on a detected restart/failure it triggers the release of the
// affected sessions (asynchronously) and re-associates.
// Ref: TS 29.244 §6.2.6.2, §6.2.2; TS 23.527 §4.2.
func (s *Server) RunPFCPNodeSupervisor(ctx context.Context) {
	backoff := s.pfcpTimers.assocRetryInitial
	for ctx.Err() == nil {
		s.setAssocState(assocSetupPending)
		if !s.runAssociationSetup(ctx) {
			if ctx.Err() != nil {
				return
			}
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-s.assocKick:
			case <-timer.C:
			}
			timer.Stop()
			backoff = min(backoff*2, s.pfcpTimers.assocRetryMax)
			continue
		}
		backoff = s.pfcpTimers.assocRetryInitial
		s.heartbeatLoop(ctx)
	}
}

func (s *Server) setAssocState(state string) {
	s.assoc.mu.Lock()
	s.assoc.state = state
	s.assoc.mu.Unlock()
}

// peerUPFAddr resolves the configured UPF N4 address.
func (s *Server) peerUPFAddr() (*net.UDPAddr, error) {
	addr, err := net.ResolveUDPAddr("udp", s.cfg.Peers.UPF)
	if err != nil {
		return nil, fmt.Errorf("smf: pfcp: resolve upf %q: %w", s.cfg.Peers.UPF, err)
	}
	return addr, nil
}

// pfcpTransact sends req to the UPF on an ephemeral socket and waits for the
// response of type wantType with the same sequence number. Per TS 29.244 §6.4
// it retransmits the SAME message (same sequence number) every T1, up to N1
// times, and returns errPFCPTimeout when they are exhausted.
func (s *Server) pfcpTransact(ctx context.Context, log *slog.Logger, req pfcpmsg.Message, wantType uint8) (pfcpmsg.Message, error) {
	peer, err := s.peerUPFAddr()
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, peer)
	if err != nil {
		return nil, fmt.Errorf("smf: pfcp: dial upf: %w", err)
	}
	defer conn.Close()
	// Unblock a pending read when ctx is cancelled.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()

	b := make([]byte, req.MarshalLen())
	if err := req.MarshalTo(b); err != nil {
		return nil, fmt.Errorf("smf: pfcp: marshal %s: %w", req.MessageTypeName(), err)
	}
	seq := req.Sequence()
	buf := make([]byte, pfcpNodeMaxDatagram)
	for attempt := 0; attempt <= s.pfcpTimers.n1; attempt++ {
		if attempt > 0 {
			log.DebugContext(ctx, "PFCP retransmission (same sequence number)",
				"interface", "N4", "direction", "OUT", "spec_ref", "TS 29.244 §6.4",
				"message_type", req.MessageTypeName(), "seq", seq, "attempt", attempt)
		}
		if _, err := conn.Write(b); err != nil {
			return nil, fmt.Errorf("smf: pfcp: send %s: %w", req.MessageTypeName(), err)
		}
		deadline := time.Now().Add(s.pfcpTimers.t1)
		_ = conn.SetReadDeadline(deadline)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if ctx.Err() != nil {
					return nil, fmt.Errorf("smf: pfcp: %w", ctx.Err())
				}
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					break // T1 expired: retransmit
				}
				// e.g. ICMP port unreachable while the UPF is down: wait out T1
				// instead of spinning, then retransmit.
				if d := time.Until(deadline); d > 0 {
					t := time.NewTimer(d)
					select {
					case <-ctx.Done():
						t.Stop()
						return nil, fmt.Errorf("smf: pfcp: %w", ctx.Err())
					case <-t.C:
					}
				}
				break
			}
			msg, perr := pfcpmsg.Parse(buf[:n])
			if perr != nil || msg.Sequence() != seq || msg.MessageType() != wantType {
				continue // not our answer
			}
			return msg, nil
		}
	}
	return nil, errPFCPTimeout
}

// runAssociationSetup performs one PFCP Association Setup attempt (CP function
// initiated, T1/N1 reliable) and returns true when the UPF accepted. The UPF
// Recovery Time Stamp in the response is logged only and never compared or
// stored as baseline (TS 23.007 §19A / TS 23.527 §4.2: it shall be ignored in
// Association Setup messages); the baseline comes from the first Heartbeat.
// Ref: TS 29.244 §6.2.6.2, §7.4.4.1/2.
func (s *Server) runAssociationSetup(ctx context.Context) bool {
	ctx = logging.WithCorrelationID(ctx, ulid.Make().String())
	log := logging.NewProcedureLogger(ctx, s.logger, procAssocSetup)
	start := time.Now()
	seq := s.nextPFCPSeq()
	req := pfcpmsg.NewAssociationSetupRequest(seq,
		pfcpie.NewNodeID("", "", "smf"),
		pfcpie.NewRecoveryTimeStamp(s.recoveryTS),
	)
	log.InfoContext(ctx, "PFCP Association Setup Request sent",
		"interface", "N4", "direction", "OUT", "spec_ref", specAssocSetup,
		"peer", s.cfg.Peers.UPF, "seq", seq, "smf_rts", fmtRTS(s.recoveryTS))

	msg, err := s.pfcpTransact(ctx, log, req, pfcpmsg.MsgTypeAssociationSetupResponse)
	if err != nil {
		if ctx.Err() != nil {
			return false
		}
		log.WarnContext(ctx, "PFCP Association Setup failed",
			"interface", "N4", "direction", "OUT", "spec_ref", specAssocSetup,
			"result", "FAILURE", "cause", causePeerNotResponding, "error", err,
			"duration_ms", time.Since(start).Milliseconds())
		metrics.ProcedureTotal.WithLabelValues("SMF", procAssocSetup, "FAILURE").Inc()
		return false
	}
	rsp, ok := msg.(*pfcpmsg.AssociationSetupResponse)
	if !ok || rsp.Cause == nil {
		log.WarnContext(ctx, "PFCP Association Setup Response without Cause",
			"interface", "N4", "direction", "IN", "spec_ref", specAssocSetup,
			"result", "FAILURE", "cause", "MISSING_CAUSE")
		metrics.ProcedureTotal.WithLabelValues("SMF", procAssocSetup, "FAILURE").Inc()
		return false
	}
	cause, _ := rsp.Cause.Cause()
	if cause != pfcpie.CauseRequestAccepted {
		log.WarnContext(ctx, "PFCP Association Setup rejected by UPF",
			"interface", "N4", "direction", "IN", "spec_ref", specAssocSetup,
			"result", "REJECT", "cause", cause)
		metrics.ProcedureTotal.WithLabelValues("SMF", procAssocSetup, "REJECT").Inc()
		return false
	}

	var peerNode string
	if rsp.NodeID != nil {
		peerNode, _ = rsp.NodeID.NodeID()
	}
	var peerRTS time.Time
	if rsp.RecoveryTimeStamp != nil {
		if t, terr := rsp.RecoveryTimeStamp.RecoveryTimeStamp(); terr == nil {
			peerRTS = rtsOf(t)
		}
	}
	if peerRTS.IsZero() {
		log.WarnContext(ctx, "PFCP Association Setup Response missing mandatory IE Recovery Time Stamp",
			"interface", "N4", "direction", "IN", "spec_ref", "TS 29.244 §7.4.4.2",
			"cause", causeRTSMissing)
	}

	s.assoc.mu.Lock()
	s.assoc.state = assocAssociated
	s.assoc.peerNodeID = peerNode
	s.assoc.associatedAt = time.Now()
	s.assoc.missingRTSWarned = false
	s.assoc.mu.Unlock()

	log.InfoContext(ctx, "PFCP Association Setup accepted",
		"interface", "N4", "direction", "IN", "spec_ref", specAssocSetup,
		"result", "OK", "cause", cause, "peer_node_id", peerNode,
		"peer_rts", fmtRTS(peerRTS), "duration_ms", time.Since(start).Milliseconds())
	metrics.ProcedureTotal.WithLabelValues("SMF", procAssocSetup, "OK").Inc()
	return true
}

// heartbeatLoop sends a Heartbeat immediately (learning the RTS baseline), then
// every heartbeat interval, until the association is lost (detection event) or
// ctx is cancelled. Ref: TS 29.244 §6.2.2.
func (s *Server) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(s.pfcpTimers.heartbeatInterval)
	defer ticker.Stop()
	s.heartbeatOnce(ctx)
	for {
		if s.PFCPAssociation().State != assocAssociated {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-s.recoverCh:
		case <-ticker.C:
			s.heartbeatOnce(ctx)
		}
	}
}

// heartbeatOnce runs one Heartbeat transaction (T1/N1). A lost transaction is a
// peer failure (TS 23.527 §4.2); a Recovery Time Stamp change is a peer restart.
func (s *Server) heartbeatOnce(ctx context.Context) {
	ctx = logging.WithCorrelationID(ctx, ulid.Make().String())
	log := logging.NewProcedureLogger(ctx, s.logger, procHeartbeat)
	seq := s.nextPFCPSeq()
	req := pfcpmsg.NewHeartbeatRequest(seq, pfcpie.NewRecoveryTimeStamp(s.recoveryTS), nil)
	msg, err := s.pfcpTransact(ctx, log, req, pfcpmsg.MsgTypeHeartbeatResponse)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		log.WarnContext(ctx, "PFCP Heartbeat transaction failed",
			"interface", "N4", "direction", "OUT", "spec_ref", specHeartbeatLost,
			"result", "FAILURE", "cause", causePeerNotResponding, "error", err, "seq", seq)
		metrics.ProcedureTotal.WithLabelValues("SMF", procHeartbeat, "FAILURE").Inc()
		s.beginRecovery(ctx, causePeerNotResponding, time.Time{}, time.Time{})
		return
	}
	rsp, ok := msg.(*pfcpmsg.HeartbeatResponse)
	if !ok {
		return
	}
	log.DebugContext(ctx, "PFCP Heartbeat Response received",
		"interface", "N4", "direction", "IN", "spec_ref", "TS 29.244 §7.4.2.2",
		"result", "OK", "seq", seq)
	s.observePeerRTS(ctx, rsp.RecoveryTimeStamp, "heartbeat_response")
}

// observePeerRTS feeds a Recovery Time Stamp learned from a Heartbeat Response
// or an inbound Heartbeat Request into the restart detection. The first value
// after an association is the baseline; a LATER value (stored < received) is a
// peer restart. An EARLIER value (stored > received) is a possible race, an older
// message arriving late: the message is obsolete and discarded (WARN, no
// recovery, baseline unchanged). A missing RTS counts as liveness only (restart
// detection disabled, WARN once per association).
// Returns true when a restart was detected.
// Ref: TS 23.007 §19A, TS 23.527 §4.2, TS 29.244 §8.2.65.
func (s *Server) observePeerRTS(ctx context.Context, ts *pfcpie.IE, source string) bool {
	log := logging.NewProcedureLogger(ctx, s.logger, procHeartbeat)
	var peerRTS time.Time
	if ts != nil {
		if t, err := ts.RecoveryTimeStamp(); err == nil {
			peerRTS = rtsOf(t)
		}
	}

	s.assoc.mu.Lock()
	if s.assoc.state != assocAssociated {
		s.assoc.mu.Unlock()
		return false
	}
	if peerRTS.IsZero() {
		warn := !s.assoc.missingRTSWarned
		s.assoc.missingRTSWarned = true
		s.assoc.mu.Unlock()
		if warn {
			log.WarnContext(ctx, "peer RTS missing — restart detection disabled",
				"interface", "N4", "direction", "IN", "spec_ref", "TS 29.244 §7.4.2.2",
				"cause", causeRTSMissing, "source", source)
		}
		return false
	}
	old := s.assoc.remoteRTS
	if old.IsZero() {
		s.assoc.remoteRTS = peerRTS
		s.assoc.mu.Unlock()
		log.InfoContext(ctx, "UPF Recovery Time Stamp baseline learned",
			"interface", "N4", "direction", "IN", "spec_ref", "TS 23.007 §19A",
			"peer_rts", fmtRTS(peerRTS), "source", source)
		return false
	}
	s.assoc.mu.Unlock()
	if old.Equal(peerRTS) {
		return false
	}
	if peerRTS.Before(old) {
		log.WarnContext(ctx, "obsolete PFCP message discarded — peer Recovery Time Stamp older than stored (possible race)",
			"interface", "N4", "direction", "IN", "spec_ref", "TS 23.007 §19A",
			"old_rts", fmtRTS(old), "received_rts", fmtRTS(peerRTS), "source", source)
		return false
	}
	return s.beginRecovery(ctx, causePeerRestart, old, peerRTS)
}

// releaseTarget is a session selected for release.
type releaseTarget struct {
	ref  string
	sess *Session
	supi string
	psi  uint8
	seid uint64
}

// beginRecovery handles a detection event (peer restart or failure): the
// association leaves ASSOCIATED (idempotent: a second detection is a no-op),
// affected sessions are moved to RELEASING under sessionMu and a release worker
// is started asynchronously (the supervisor never waits for it).
//
// Restart (new RTS later than the stored one, enforced by observePeerRTS):
// sessions N4-established before the new UPF RTS are stale (cutoff = new UPF
// RTS; assumes SMF and UPF share a clock, e.g. same Docker host, else NTP sync
// is required). Failure: all sessions.
// Ref: TS 23.527 §4.2 (detection), §4.3 (restoration by release).
func (s *Server) beginRecovery(ctx context.Context, cause string, oldRTS, newRTS time.Time) bool {
	s.assoc.mu.Lock()
	if s.assoc.state != assocAssociated {
		s.assoc.mu.Unlock()
		return false
	}
	s.assoc.state = assocRecovering
	s.assoc.remoteRTS = time.Time{}
	s.assoc.missingRTSWarned = false
	s.assoc.mu.Unlock()

	ctx = logging.WithCorrelationID(ctx, ulid.Make().String())
	log := logging.NewProcedureLogger(ctx, s.logger, procRecovery)

	restart := cause == causePeerRestart
	allSessions := !restart
	targets := s.markSessionsReleasing(newRTS, allSessions, restart)

	spec := specDetect
	restoreRef := specRestorePeerFailure
	if restart {
		restoreRef = specRestorePeerRestart
	}
	log.WarnContext(ctx, "PFCP peer restart/failure detected — releasing affected PDU sessions",
		"interface", "N4", "direction", "IN", "spec_ref", spec,
		"cause", cause, "old_rts", fmtRTS(oldRTS), "new_rts", fmtRTS(newRTS),
		"stale_sessions", len(targets), "restoration_spec_ref", restoreRef)
	metrics.ProcedureTotal.WithLabelValues("SMF", procRecovery, "OK").Inc()

	select {
	case s.recoverCh <- struct{}{}:
	default:
	}

	if len(targets) > 0 {
		s.releaseWG.Add(1)
		go func() {
			defer s.releaseWG.Done()
			s.releaseSessions(ctx, targets)
		}()
	}
	return true
}

// markSessionsReleasing selects the stale sessions under sessionMu and moves
// them to RELEASING (the state transition is the idempotency guard). With all
// set every non-RELEASING session is selected, otherwise those whose N4
// establishment time (CreatedAt fallback) is before cutoff.
func (s *Server) markSessionsReleasing(cutoff time.Time, all, n4Stale bool) []releaseTarget {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	var out []releaseTarget
	for ref, sess := range s.sessions {
		if sess.State == sessionStateReleasing {
			continue
		}
		established := sess.N4EstablishedAt
		if established.IsZero() {
			established = sess.CreatedAt
		}
		if !all && !established.Before(cutoff) {
			continue
		}
		sess.State = sessionStateReleasing
		if n4Stale {
			sess.N4Stale = true
		}
		out = append(out, releaseTarget{ref: ref, sess: sess, supi: sess.SUPI, psi: sess.PDUSessionID, seid: sess.SEID})
	}
	return out
}

// releaseSessions releases the targets towards the AMF with bounded
// concurrency; any failure falls back to a local release.
func (s *Server) releaseSessions(runCtx context.Context, targets []releaseTarget) {
	// The release calls must complete even when the supervisor stops; only the
	// RELEASING guard timers follow runCtx.
	ctx := context.WithoutCancel(runCtx)
	work := make(chan releaseTarget)
	var wg sync.WaitGroup
	workers := min(amfReleaseConcurrency, len(targets))
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range work {
				s.releaseOne(ctx, runCtx, t)
			}
		}()
	}
	for _, t := range targets {
		work <- t
	}
	close(work)
	wg.Wait()
}

// releaseOne asks the AMF to release the PDU session towards the UE (N1/N2) via
// its management API; on failure it releases the SM context locally.
// DEVIATION: AMF management API instead of Namf_Communication_N1N2MessageTransfer
// (TS 23.502 §4.3.4.2) because the AMF producer does not forward N1/N2 yet.
func (s *Server) releaseOne(ctx, runCtx context.Context, t releaseTarget) {
	log := logging.NewProcedureLogger(ctx, s.logger, procRecovery)
	attrs := []any{
		"interface", "Namf-mgmt", "direction", "OUT", "spec_ref", specAMFRelease,
		"supi", t.supi, "pdu_session_id", t.psi, "seid", t.seid,
	}
	err := s.requestAMFRelease(ctx, t.supi, t.psi)
	if err == nil {
		log.InfoContext(ctx, "AMF asked to release PDU session after UPF restart/failure",
			append(attrs, "result", "OK")...)
		s.startReleaseGuard(runCtx, ctx, t)
		return
	}
	log.WarnContext(ctx, "AMF release failed — releasing SM context locally (known limitation)",
		append(attrs, "result", "FAILURE", "cause", causeAMFReleaseFailed, "error", err)...)
	metrics.ProcedureTotal.WithLabelValues("SMF", procRecovery, "FAILURE").Inc()
	s.releaseSessionLocal(ctx, t.ref, t.sess, true)
}

// startReleaseGuard arms the RELEASING-session safety timer: when the AMF
// accepted the release request but the ReleaseSMContext never arrives, the SMF
// frees the session itself after pfcpNodeTimers.releaseGuard (idempotent via
// releaseSessionLocal). The goroutine ends on runCtx cancellation, so it never
// outlives the supervisor. Ref: TS 23.502 §4.3.4.2.
func (s *Server) startReleaseGuard(runCtx, relCtx context.Context, t releaseTarget) {
	guard := s.pfcpTimers.releaseGuard
	if guard <= 0 {
		return
	}
	s.guardWG.Add(1)
	go func() {
		defer s.guardWG.Done()
		timer := time.NewTimer(guard)
		defer timer.Stop()
		select {
		case <-runCtx.Done():
			return
		case <-timer.C:
		}
		s.sessionMu.Lock()
		stillReleasing := s.sessions[t.ref] == t.sess && t.sess.State == sessionStateReleasing
		s.sessionMu.Unlock()
		if !stillReleasing {
			return
		}
		log := logging.NewProcedureLogger(relCtx, s.logger, procRecovery)
		if s.releaseSessionLocal(relCtx, t.ref, t.sess, true) {
			metrics.ProcedureTotal.WithLabelValues("SMF", procRecovery, "FAILURE").Inc()
			log.WarnContext(relCtx, "RELEASING session not released by AMF within guard time — released locally",
				"interface", "N11", "direction", "OUT", "spec_ref", specAMFRelease,
				"supi", t.supi, "pdu_session_id", t.psi, "seid", t.seid,
				"result", "OK", "cause", "RELEASE_GUARD_EXPIRED", "guard_ms", guard.Milliseconds())
		}
	}()
}

// WaitReleaseGuards blocks until all RELEASING guard timers have ended (they end
// on supervisor ctx cancellation or after firing); used by tests.
func (s *Server) WaitReleaseGuards() { s.guardWG.Wait() }

// requestAMFRelease calls DELETE /amf/v1/ue-contexts/{supi}/pdu-sessions/{psi}
// on the AMF management API (plain HTTP, non-3GPP) with the detection event's
// X-Correlation-Id. 200/202/204 are success.
func (s *Server) requestAMFRelease(ctx context.Context, supi string, psi uint8) error {
	if s.cfg.Peers.AMFMgmt == "" {
		return fmt.Errorf("smf: amf_mgmt peer not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, amfReleaseTimeout)
	defer cancel()
	u := fmt.Sprintf("http://%s/amf/v1/ue-contexts/%s/pdu-sessions/%d",
		s.cfg.Peers.AMFMgmt, url.PathEscape(supi), psi)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return fmt.Errorf("smf: build AMF release request: %w", err)
	}
	if id := logging.CorrelationID(ctx); id != "" {
		req.Header.Set("X-Correlation-Id", id)
	}
	resp, err := s.mgmtHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("smf: AMF pdu session release: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted, http.StatusNoContent:
		return nil
	}
	return fmt.Errorf("smf: AMF pdu session release: status %d", resp.StatusCode)
}

// handlePFCPHeartbeatRequest answers an inbound Heartbeat Request on the
// receiver socket with the SMF Recovery Time Stamp and, when it comes from the
// UPF peer, feeds its RTS into the restart detection. Ref: TS 29.244 §6.2.2.
func (s *Server) handlePFCPHeartbeatRequest(ctx context.Context, conn *net.UDPConn, raddr *net.UDPAddr, req *pfcpmsg.HeartbeatRequest) {
	ctx = logging.WithCorrelationID(ctx, ulid.Make().String())
	log := logging.NewProcedureLogger(ctx, s.logger, procHeartbeat)
	resp := pfcpmsg.NewHeartbeatResponse(req.Sequence(), pfcpie.NewRecoveryTimeStamp(s.recoveryTS))
	b, err := resp.Marshal()
	if err != nil {
		log.ErrorContext(ctx, "PFCP Heartbeat Response marshal failed",
			"interface", "N4", "direction", "OUT", "error", fmt.Errorf("smf: heartbeat: %w", err))
		return
	}
	if _, err := conn.WriteToUDP(b, raddr); err != nil {
		log.WarnContext(ctx, "PFCP Heartbeat Response send failed",
			"interface", "N4", "direction", "OUT", "error", fmt.Errorf("smf: heartbeat: %w", err), "remote", raddr)
		return
	}
	log.DebugContext(ctx, "PFCP Heartbeat Request answered",
		"interface", "N4", "direction", "IN", "spec_ref", "TS 29.244 §7.4.2.1",
		"seq", req.Sequence(), "remote", raddr)
	if s.isUPFPeer(raddr) {
		s.observePeerRTS(ctx, req.RecoveryTimeStamp, "heartbeat_request")
	}
}

// isUPFPeer reports whether raddr's IP is the configured UPF peer (the UPF may
// send from a source port other than 8805).
func (s *Server) isUPFPeer(raddr *net.UDPAddr) bool {
	peer, err := s.peerUPFAddr()
	if err != nil || raddr == nil {
		return false
	}
	return peer.IP.Equal(raddr.IP)
}

// skipN4ForReleasing reports (DEBUG log) that N4 signalling for a session in
// RELEASING state is skipped, so an AN release racing the recovery does not hit
// the (new) UPF with an unknown SEID.
func (s *Server) skipN4ForReleasing(sess *Session, op string) bool {
	s.sessionMu.Lock()
	releasing := sess.State == sessionStateReleasing
	s.sessionMu.Unlock()
	if releasing {
		s.logger.Debug("PFCP "+op+" skipped — session RELEASING after UPF restart/failure",
			"procedure", procRecovery, "interface", "N4", "direction", "OUT",
			"nf", "SMF", "correlation_id", ulid.Make().String(),
			"spec_ref", specRestore, "seid", sess.SEID, "supi", sess.SUPI)
	}
	return releasing
}

// warnIfNotAssociated logs a WARN and nudges an immediate Association Setup
// attempt when a PDU session is created without a PFCP association. The
// establishment still proceeds (MVP, the UPF does not enforce association).
func (s *Server) warnIfNotAssociated(ctx context.Context, corrID string) {
	st := s.PFCPAssociation().State
	if st == assocAssociated {
		return
	}
	s.logger.WarnContext(ctx, "no PFCP association with UPF — proceeding with PDU session establishment",
		"procedure", procAssocSetup, "interface", "N4", "direction", "OUT",
		"spec_ref", "TS 29.244 §6.2.6.1", "correlation_id", corrID, "association_state", st)
	select {
	case s.assocKick <- struct{}{}:
	default:
	}
}
