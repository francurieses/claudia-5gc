package ngap

import (
	"context"
	"fmt"
	"time"

	"github.com/francurieses/claudia-5gc/shared/logging"
	libngap "github.com/francurieses/claudia-5gc/shared/ngap"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

// procNGReset is the procedure label of the NG Reset logs and metrics.
const procNGReset = "NGReset"

// ngResetANReleaseTimeout bounds the SMF user-plane deactivation of one UE released by an NG
// RESET. The call runs detached from the SCTP read context (context.WithoutCancel), so it
// needs its own deadline; it is an implementation bound, not a 3GPP timer (the SBI
// request budget of TS 29.500 §6.1 applies per attempt).
const ngResetANReleaseTimeout = 10 * time.Second

// ngResetIEIDResetType is the id of the Reset Type IE (TS 38.413 §9.2.6.11), reported in the
// Criticality Diagnostics of an unusable Reset Type.
const ngResetIEIDResetType = ngapType.ProtocolIEIDResetType

// Spec references of the NG Reset procedure (NG-RAN node initiated).
const (
	refNGResetRecv = "TS 38.413 §8.7.4.2.2"
	refNGResetAck  = "TS 38.413 §9.2.6.12"
	refNGResetSMF  = "TS 23.502 §4.2.6 step 5"
)

// ResetItem is one UE-associated logical NG-connection item of NG RESET / NG RESET
// ACKNOWLEDGE (TS 38.413 §9.3.3.1/§9.3.3.2). Pointers preserve the IE presence so the
// acknowledge echoes exactly the IDs that were received.
type ResetItem struct {
	AMF *int64
	RAN *int64
}

// NGResetMsg is the decoded NG RESET (TS 38.413 §9.2.6.11).
type NGResetMsg struct {
	// Cause is the Cause IE (criticality ignore, TS 38.413 §9.2.6.11); informational only.
	Cause *ngapType.Cause
	// HasResetType is false when IE 88 was absent (caught earlier by the §10.3.5 check).
	HasResetType bool
	// ResetAll is true for the nG-Interface alternative.
	ResetAll bool
	// PartOf is true for the partOfNG-Interface alternative; Items holds its list.
	PartOf bool
	Items  []ResetItem
	// NotifyCD carries the Criticality Diagnostics of "ignore and notify" IEs (§10.3.4.2).
	NotifyCD *ngapType.CriticalityDiagnostics
}

// extractNGReset converts a decoded NG RESET into NGResetMsg.
func extractNGReset(req *ngapType.NGReset) *NGResetMsg {
	out := &NGResetMsg{}
	for _, ie := range req.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDCause:
			out.Cause = ie.Value.Cause
		case ngapType.ProtocolIEIDResetType:
			rt := ie.Value.ResetType
			if rt == nil {
				continue
			}
			out.HasResetType = true
			switch rt.Present {
			case ngapType.ResetTypePresentNGInterface:
				out.ResetAll = true
			case ngapType.ResetTypePresentPartOfNGInterface:
				out.PartOf = true
				if rt.PartOfNGInterface != nil {
					for _, it := range rt.PartOfNGInterface.List {
						var ri ResetItem
						if it.AMFUENGAPID != nil {
							v := it.AMFUENGAPID.Value
							ri.AMF = &v
						}
						if it.RANUENGAPID != nil {
							v := it.RANUENGAPID.Value
							ri.RAN = &v
						}
						out.Items = append(out.Items, ri)
					}
				}
			}
		}
	}
	return out
}

// BuildNGResetAcknowledge builds NG RESET ACKNOWLEDGE (SuccessfulOutcome, procedure code
// 20, criticality reject). IEs in spec order: UE-associated Logical NG-connection List
// (id 111, ignore), Criticality Diagnostics (id 19, ignore). Items are echoed in the given
// order; empty items (neither ID) are skipped and the list IE is omitted when nothing
// remains (SIZE(1..65536)). Ref: TS 38.413 §9.2.6.12, §8.7.4.2.2.
func BuildNGResetAcknowledge(items []ResetItem, cd *ngapType.CriticalityDiagnostics) ([]byte, error) {
	var list []ngapType.UEAssociatedLogicalNGConnectionItem
	for _, it := range items {
		if it.AMF == nil && it.RAN == nil {
			continue
		}
		var li ngapType.UEAssociatedLogicalNGConnectionItem
		if it.AMF != nil {
			li.AMFUENGAPID = &ngapType.AMFUENGAPID{Value: *it.AMF}
		}
		if it.RAN != nil {
			li.RANUENGAPID = &ngapType.RANUENGAPID{Value: *it.RAN}
		}
		list = append(list, li)
	}
	var ies []ngapType.NGResetAcknowledgeIEs
	if len(list) > 0 {
		ies = append(ies, ngapType.NGResetAcknowledgeIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDUEAssociatedLogicalNGConnectionList},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.NGResetAcknowledgeIEsValue{
				Present:                             ngapType.NGResetAcknowledgeIEsPresentUEAssociatedLogicalNGConnectionList,
				UEAssociatedLogicalNGConnectionList: &ngapType.UEAssociatedLogicalNGConnectionList{List: list},
			},
		})
	}
	if cd != nil {
		ies = append(ies, ngapType.NGResetAcknowledgeIEs{
			Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDCriticalityDiagnostics},
			Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.NGResetAcknowledgeIEsValue{
				Present:                ngapType.NGResetAcknowledgeIEsPresentCriticalityDiagnostics,
				CriticalityDiagnostics: cd,
			},
		})
	}
	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentSuccessfulOutcome,
		SuccessfulOutcome: &ngapType.SuccessfulOutcome{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeNGReset},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
			Value: ngapType.SuccessfulOutcomeValue{
				Present: ngapType.SuccessfulOutcomePresentNGResetAcknowledge,
				NGResetAcknowledge: &ngapType.NGResetAcknowledge{
					ProtocolIEs: ngapType.ProtocolIEContainerNGResetAcknowledgeIEs{List: ies},
				},
			},
		},
	}
	b, err := libngap.Encoder(pdu)
	if err != nil {
		return nil, fmt.Errorf("ngap: encode NG Reset Acknowledge: %w", err)
	}
	return b, nil
}

// handleNGReset processes an NG RESET from the NG-RAN node: it releases the indicated
// UE-associated logical NG-connections locally (CM-CONNECTED -> CM-IDLE, no UE CONTEXT
// RELEASE COMMAND), then answers NG RESET ACKNOWLEDGE, then asks the SMF to deactivate the
// user plane of the released UEs. Ref: TS 38.413 §8.7.4.2.2, §9.2.6.11, §9.2.6.12.
func (s *Server) handleNGReset(ctx context.Context, gnb *GNBContext, msg *Message) {
	log := logging.NewProcedureLogger(ctx, s.logger, procNGReset).With(
		"interface", "N2", "gnb_addr", gnb.remoteAddrString())
	req, ok := msg.Value.(*NGResetMsg)
	if !ok || req == nil || (!req.ResetAll && !req.PartOf) {
		// Reset Type absent or an unknown (choice-extensions) alternative: the AMF cannot
		// tell which associations to reset. Ref: TS 38.413 §10.3.4.2.
		log.Warn("NG Reset with unusable Reset Type rejected",
			"direction", "IN", "message_type", "NGReset", "result", "REJECT",
			"spec_ref", "TS 38.413 §10.3.4.2")
		metrics.ProcedureTotal.WithLabelValues("AMF", procNGReset, "REJECT").Inc()
		// abstract-syntax-error-reject + Criticality Diagnostics (procedure code, triggering
		// message, procedure criticality, IE 88 as not understood), §10.3.4.2.
		cd := cdFor(msg, []ieFinding{{id: ngResetIEIDResetType,
			crit: ngapType.CriticalityPresentReject, typ: ngapType.TypeOfErrorPresentNotUnderstood}}, true)
		if err := s.sendErrorIndication(ctx, gnb, ErrorIndicationParams{
			CausePresent: ngapType.CausePresentProtocol,
			CauseValue:   int64(ngapType.CauseProtocolPresentAbstractSyntaxErrorReject),
			CD:           &cd,
		}, "TS 38.413 §10.3.4.2"); err != nil {
			log.Error("ERROR INDICATION for unusable Reset Type not sent", "direction", "OUT",
				"message_type", "ErrorIndication", "result", "FAILURE", "error", err,
				"spec_ref", "TS 38.413 §10.3.4.2")
		}
		return
	}

	s.observeNGReset(gnb)

	resetType := "all"
	if req.PartOf {
		resetType = "partial"
	}
	cause := "absent"
	if req.Cause != nil {
		cause = causeName(req.Cause.Present, ngResetCauseValue(req.Cause))
	}
	gnb.mu.Lock()
	gnbName := gnb.Name
	gnb.mu.Unlock()
	log.Info("NG Reset received",
		"direction", "IN", "message_type", "NGReset", "spec_ref", refNGResetRecv,
		"gnb_name", gnbName, "gnb_id", gnb.remoteAddrString(),
		"reset_type", resetType, "items", len(req.Items), "cause", cause, "result", "OK")

	released, unknown := s.releaseForNGReset(ctx, gnb, req)
	metrics.NGResetUEsReleasedTotal.WithLabelValues("AMF", resetType).Add(float64(len(released)))

	// Acknowledge after the local release (§8.7.4.2.2). Reset-all carries no list.
	var echo []ResetItem
	if req.PartOf {
		echo = req.Items
	}
	ackFields := []any{"direction", "OUT", "message_type", "NGResetAcknowledge",
		"spec_ref", refNGResetAck, "gnb_name", gnbName, "released", len(released), "unknown", unknown}
	if pdu, err := BuildNGResetAcknowledge(echo, req.NotifyCD); err != nil {
		log.Error("NG Reset Acknowledge build failed", append(ackFields, "result", "FAILURE", "error", err)...)
		metrics.ProcedureTotal.WithLabelValues("AMF", procNGReset, "FAILURE").Inc()
	} else if _, err := gnb.writeNGAP(pdu); err != nil {
		log.Error("NG Reset Acknowledge send failed", append(ackFields, "result", "FAILURE", "error", err)...)
		metrics.ProcedureTotal.WithLabelValues("AMF", procNGReset, "FAILURE").Inc()
	} else {
		log.Info("NG Reset Acknowledge sent", append(ackFields, "result", "OK")...)
		metrics.ProcedureTotal.WithLabelValues("AMF", procNGReset, "OK").Inc()
	}

	// SMF leg: deactivate the user plane of each UE that stays registered (same path as
	// the AN Release, TS 23.502 §4.2.6 step 5), off the SCTP loop on the UE serial queue.
	if s.onANRelease == nil {
		log.Warn("NG Reset: no AN release handler wired, SMF user plane not deactivated",
			"direction", "OUT", "interface", "N11", "gnb_name", gnbName, "released", len(released),
			"result", "FAILURE", "spec_ref", refNGResetSMF)
		return
	}
	detached := context.WithoutCancel(ctx)
	for _, ue := range released {
		ue := ue
		ue.EnqueueSerial(func() {
			c, cancel := context.WithTimeout(detached, ngResetANReleaseTimeout)
			defer cancel()
			s.onANRelease(c, ue)
		})
	}
}

// ngResetCauseValue returns the enumerated value of the selected Cause alternative.
func ngResetCauseValue(c *ngapType.Cause) int64 {
	switch c.Present {
	case ngapType.CausePresentRadioNetwork:
		if c.RadioNetwork != nil {
			return int64(c.RadioNetwork.Value)
		}
	case ngapType.CausePresentTransport:
		if c.Transport != nil {
			return int64(c.Transport.Value)
		}
	case ngapType.CausePresentNas:
		if c.Nas != nil {
			return int64(c.Nas.Value)
		}
	case ngapType.CausePresentProtocol:
		if c.Protocol != nil {
			return int64(c.Protocol.Value)
		}
	case ngapType.CausePresentMisc:
		if c.Misc != nil {
			return int64(c.Misc.Value)
		}
	}
	return 0
}

// releaseForNGReset resolves the affected associations of this gNB and releases them
// locally. It returns the UEs that stay registered (those needing the SMF deactivation)
// and the number of list items that matched no association on this NG interface.
func (s *Server) releaseForNGReset(ctx context.Context, gnb *GNBContext, req *NGResetMsg) (keep []*amfctx.UEContext, unknown int) {
	type target struct {
		ue  *amfctx.UEContext
		ran int64
	}
	var targets []target
	seen := map[*amfctx.UEContext]bool{}
	add := func(ue *amfctx.UEContext, ran int64) {
		if !seen[ue] {
			seen[ue] = true
			targets = append(targets, target{ue, ran})
		}
	}

	gnb.mu.Lock()
	if req.ResetAll {
		for ran, ue := range gnb.UEs {
			add(ue, ran)
		}
	} else {
		for _, it := range req.Items {
			if it.AMF == nil && it.RAN == nil {
				continue // §8.7.4.4.1: empty item, nothing to identify, ignored
			}
			matched := false
			if it.AMF != nil {
				if ue, ok := s.mgr.GetByNGAPId(*it.AMF); ok {
					for ran, cand := range gnb.UEs {
						if cand == ue {
							add(ue, ran)
							matched = true
							break
						}
					}
				}
			}
			if it.RAN != nil {
				if ue, ok := gnb.UEs[*it.RAN]; ok {
					add(ue, *it.RAN)
					matched = true
				}
			}
			if !matched {
				unknown++
			}
		}
	}
	gnb.mu.Unlock()

	// After a completed N2 handover the source gNB still lists the UE until its UE CONTEXT
	// RELEASE COMPLETE: such a stale entry is only dropped, the UE is served elsewhere now.
	// (Checked outside gnb.mu: isStaleSourceRelease takes the UE lock.)
	live := make([]target, 0, len(targets))
	for _, t := range targets {
		if !isStaleSourceRelease(t.ue, gnb, t.ran) {
			live = append(live, t)
		}
	}
	gnb.mu.Lock()
	for _, t := range targets {
		delete(gnb.UEs, t.ran)
	}
	gnb.mu.Unlock()
	targets = live

	affected := make([]*amfctx.UEContext, 0, len(targets))
	for _, t := range targets {
		affected = append(affected, t.ue)
	}
	s.abortPendingN2HOForReset(gnb, req, affected)

	log := logging.NewProcedureLogger(ctx, s.logger, procNGReset).With("interface", "N2")
	for _, t := range targets {
		ue := t.ue
		ue.AbortRegAccept()
		ue.ClearRegProc()
		ue.Lock()
		ue.CMState = amfctx.CMIdle // guarded by ue.mu: one critical section with the fields below
		ue.UEAMBRSentToRAN = false
		pending := ue.PendingRemoval
		neverRegistered := ue.State == amfctx.GMMDeregistered && len(ue.PDUSessions) == 0
		amfID := ue.AMFUENGAPId
		if pending && ue.PendingRemovalTimer != nil {
			ue.PendingRemovalTimer.Stop()
		}
		supi := ue.SUPI
		ue.Unlock()

		log.Info("UE-associated logical NG-connection released by NG Reset — UE is CM-IDLE",
			"direction", "IN", "message_type", "NGReset", "spec_ref", refNGResetRecv,
			"supi", supi, "amf_ue_ngap_id", amfID, "ran_ue_ngap_id", t.ran,
			"cm_state", "CM-IDLE", "pending_removal", pending, "result", "OK")

		if pending || neverRegistered {
			// Deregistration owns the sessions / nothing registered to keep (TS 24.501 §5.3.7).
			s.mgr.Remove(ctx, ue)
			continue
		}
		gnb.mu.Lock()
		if gnb.IdleUEs == nil {
			gnb.IdleUEs = make(map[int64]*amfctx.UEContext)
		}
		gnb.IdleUEs[t.ran] = ue
		gnb.mu.Unlock()
		s.StartMobileReachableTimer(ue)
		keep = append(keep, ue)
	}
	return keep, unknown
}

// abortPendingN2HOForReset aborts the N2 handovers of the released UEs (source side) and,
// for a reset of the target gNB, the prepared handovers towards it: the UE stays on its
// source association. Ref: TS 38.413 §8.7.4.2.2 (other procedures on the associations
// are aborted).
func (s *Server) abortPendingN2HOForReset(gnb *GNBContext, req *NGResetMsg, ues []*amfctx.UEContext) {
	s.pendingN2HOMu.Lock()
	defer s.pendingN2HOMu.Unlock()
	for _, ue := range ues {
		ue.Lock()
		id := ue.AMFUENGAPId
		ue.Unlock()
		delete(s.pendingN2HO, id)
	}
	for id, st := range s.pendingN2HO {
		if st.targetGNB != gnb {
			continue
		}
		if req.ResetAll {
			delete(s.pendingN2HO, id)
			continue
		}
		for _, it := range req.Items {
			// The target association is identified by AMF and target RAN UE NGAP ID; an
			// item carrying only one of them matches on that one.
			amfOK := it.AMF == nil || *it.AMF == id
			ranOK := it.RAN == nil || *it.RAN == st.targetRANUENGAPId
			if (it.AMF != nil || it.RAN != nil) && amfOK && ranOK {
				delete(s.pendingN2HO, id)
				break
			}
		}
	}
}

// isReleasedAssociation reports whether (ranID, ue) is a UE-associated logical
// NG-connection of this gNB that was released (NG Reset / AN release: the UE is parked in
// IdleUEs and no longer in UEs). A gNB that keeps using such a pair is out of sync.
// Ref: TS 38.413 §8.7.4.2.2, §10.6.
func (g *GNBContext) isReleasedAssociation(ranID int64, ue *amfctx.UEContext) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.IdleUEs[ranID] == ue && g.UEs[ranID] != ue
}
