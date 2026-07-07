package sbi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	nasmsg "github.com/francurieses/claudia-5gc/nf/amf/internal/nas"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
)

const nfName = "AMF"

// Config configures the inbound SBI server.
type Config struct {
	Address  string // host:port, e.g. 0.0.0.0:8001
	CertFile string
	KeyFile  string
	CAFile   string
}

// Pager triggers an NGAP Paging for a CM-IDLE UE. Implemented by the NGAP server.
// Ref: TS 38.413 §9.2.8, TS 23.502 §4.2.3.3.
type Pager interface {
	SendPaging(ue *amfctx.UEContext) error
}

// locationTimeout is the maximum time the Namf_Location handler will block
// waiting for an NGAP LocationReport from the gNB after sending a
// LocationReportingControl. A direct (EventType=Direct) report must be immediate;
// 10 s provides a generous safety margin for congested N2 paths.
//
// Ref: TS 38.413 §8.17.1; TS 23.273 §7.2 (no normative timer defined for Cell-ID
// positioning, so this is an implementation-defined guard value).
const locationTimeout = 10 * time.Second

// pageTimeout is the T-positioning guard timer: the maximum time to wait for the
// UE to respond to paging and return to CM-CONNECTED before giving up on deferred
// MT location. Implementation-defined per TS 23.273 §6.3.
const pageTimeout = 15 * time.Second

// Locator triggers an NGAP LocationReportingControl for a CM-CONNECTED UE and
// returns a channel on which the LocationResult will be delivered when the gNB
// responds with an NGAP LocationReport. The pending map entry is owned by the
// ngap.Server; the caller must ensure the entry is cleaned up on timeout by
// calling the returned cleanup function.
//
// Implemented by ngap.Server; defined here to avoid an import cycle.
// Ref: TS 38.413 §8.17.1; TS 29.518 §5.2.2.6.
type Locator interface {
	SendLocationReportingControl(ue *amfctx.UEContext) (<-chan ngap.LocationResult, error)
}

// NRPPaRelay sends an opaque NRPPa PDU to the gNB serving a given UE via an
// NGAP DownlinkUEAssociatedNRPPaTransport message (ProcCode=8) and returns a
// channel on which the matching UL NRPPa PDU will be delivered when the gNB
// responds. The AMF is a pure relay — it must NOT parse the NRPPa bytes.
//
// Implemented by ngap.Server; defined here to avoid an import cycle.
// Ref: TS 38.413 §8.17.3; TS 23.273 §7.2 step C; TS 29.518 §5.2.2.6.
type NRPPaRelay interface {
	SendDownlinkNRPPa(ue *amfctx.UEContext, nrppaPDU []byte, routingID []byte) (<-chan ngap.NRPPaResult, error)
}

// LPPRelay sends an opaque LPP PDU to the UE via a DL NAS Transport (payload
// container type 0x03, TS 24.501 §8.7.4) and returns a channel on which the
// matching UL LPP PDU will be delivered when the UE responds. The AMF is a
// pure relay — it must NOT parse the LPP bytes.
//
// Implemented by nasmsg.Handler; defined here to mirror NRPPaRelay's
// decoupling from the concrete producer package (nf/amf/internal/nas), wired
// by SetLPPRelay in main.go.
// Ref: TS 24.501 §8.7.4; TS 23.273 §7.2; TS 29.518 §5.2.2.6; LMF-005.
type LPPRelay interface {
	SendDownlinkLPP(ue *amfctx.UEContext, lppPDU []byte) (<-chan nasmsg.LPPResult, error)
	// SendDownlinkLPPNoWait sends the DL NAS Transport without registering a
	// pendingLPP waiter — the LMF-009 DL-only leg (expectUlResponse=false,
	// ProvideAssistanceData: unsolicited, no LPP response message exists).
	// Ref: TS 37.355 §6.5.2; docs/procedures/LPPRelay.md §Endpoints.
	SendDownlinkLPPNoWait(ue *amfctx.UEContext, lppPDU []byte) error
}

// Server is the AMF inbound SBI server (namf-comm + namf-loc).
// Ref: TS 29.518 §5.3.2, §5.2.2.6.
type Server struct {
	cfg     Config
	mgr     *amfctx.Manager
	logger  *slog.Logger
	httpSrv *http.Server
	pager   Pager
	locator Locator
	// nrppaRelay sends DL NRPPa PDUs and delivers the matching UL NRPPa PDU.
	// Implemented by ngap.Server; wired by SetNRPPaRelay in main.go.
	// Ref: TS 38.413 §8.17.3.
	nrppaRelay NRPPaRelay
	// lppRelay sends DL LPP PDUs (over NAS N1) and delivers the matching UL
	// LPP PDU. Implemented by nasmsg.Handler; wired by SetLPPRelay in
	// main.go. Nil = dl-lpp-info always fails (503), signalling the LMF to
	// fall back to E-CID/Cell-ID. Ref: TS 24.501 §8.7.4; LMF-005.
	lppRelay LPPRelay
	// pendingLocPage holds in-flight paging-then-locate waiters. Keyed by
	// AMF-UE-NGAP-ID; value is a buffered chan struct{} (cap 1) that is closed
	// when the UE returns to CM-CONNECTED via a Service Request.
	// Ref: TS 23.273 §7.2 steps E2–E7.
	pendingLocPage sync.Map
}

// NotifyUEReachable is called by the NAS onUEReachable callback whenever a UE
// enters CM-CONNECTED. It unblocks any Namf_Location paging-then-locate waiter
// for that UE so positioning can proceed.
// Ref: TS 23.273 §7.2 steps E2–E7; TS 23.502 §4.2.3.3.
func (s *Server) NotifyUEReachable(amfUENGAPId int64) {
	if v, ok := s.pendingLocPage.LoadAndDelete(amfUENGAPId); ok {
		if ch, ok := v.(chan struct{}); ok {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
}

// SetPager wires the NGAP paging trigger used by N1N2MessageTransfer.
func (s *Server) SetPager(p Pager) { s.pager = p }

// SetLocator wires the NGAP location trigger used by Namf_Location_ProvideLocationInfo.
// Must be called before Start(). Ref: TS 29.518 §5.2.2.6; TS 38.413 §8.17.1.
func (s *Server) SetLocator(l Locator) { s.locator = l }

// SetNRPPaRelay wires the NGAP NRPPa relay used by Namf_Location dl-nrppa-info.
// Must be called before Start(). Ref: TS 38.413 §8.17.3; TS 29.518 §5.2.2.6.
func (s *Server) SetNRPPaRelay(r NRPPaRelay) { s.nrppaRelay = r }

// SetLPPRelay wires the NAS LPP relay used by Namf_Location dl-lpp-info.
// Must be called before Start(). Ref: TS 24.501 §8.7.4; TS 29.518 §5.2.2.6.
func (s *Server) SetLPPRelay(r LPPRelay) { s.lppRelay = r }

// New builds the inbound SBI server. It does not start listening — call Start.
func New(cfg Config, mgr *amfctx.Manager, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{cfg: cfg, mgr: mgr, logger: logger}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /namf-comm/v1/ue-contexts/{ueContextId}/transfer", s.handleUEContextTransfer)
	mux.HandleFunc("POST /namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages", s.handleN1N2MessageTransfer)
	// Namf_Location_ProvideLocationInfo — Cell-ID positioning relay.
	// Ref: TS 29.518 §5.2.2.6; TS 23.273 §7.2.
	mux.HandleFunc("POST /namf-loc/v1/ue-contexts/{ueContextId}/provide-loc-info", s.handleProvideLocInfo)
	// Namf_Location dl-nrppa-info: LMF sends DL NRPPa PDU; AMF relays to gNB and waits for UL NRPPa.
	// Ref: TS 29.518 §5.2.2.6 (NRPPa relay extension); TS 38.413 §8.17.3.
	mux.HandleFunc("POST /namf-loc/v1/ue-contexts/{ueContextId}/dl-nrppa-info", s.handleDLNRPPaInfo)
	// Namf_Location dl-lpp-info: LMF sends DL LPP PDU; AMF relays it to the UE
	// over N1 (DL NAS Transport, payload container type 0x03) and waits for
	// the matching UL LPP PDU. Ref: TS 29.518 §5.2.2.6; TS 24.501 §8.7.4; LMF-005.
	mux.HandleFunc("POST /namf-loc/v1/ue-contexts/{ueContextId}/dl-lpp-info", s.handleDLLPPInfo)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tlsCfg, err := loadTLSConfig(cfg.CertFile, cfg.KeyFile, cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("amf: sbi: load TLS config: %w", err)
	}

	s.httpSrv = &http.Server{
		Addr:              cfg.Address,
		Handler:           otelhttp.NewHandler(s.middleware(mux), "AMF"),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s, nil
}

// HTTPHandler exposes the configured request handler (mux + middleware) for
// in-process functional tests that drive the server without TLS.
func (s *Server) HTTPHandler() http.Handler { return s.httpSrv.Handler }

// Start runs the SBI server until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(shutCtx)
	}()

	s.logger.Info("AMF inbound SBI server listening",
		"addr", s.cfg.Address,
		"service", "namf-comm",
		"spec_ref", "TS 29.518 §5.3.2",
	)

	var err error
	if s.httpSrv.TLSConfig != nil {
		// ALPN rule: TLSConfig (with NextProtos h2) must be set before ConfigureServer.
		// Ref: TS 29.500 §4.4.2.
		_ = http2.ConfigureServer(s.httpSrv, &http2.Server{})
		err = s.httpSrv.ListenAndServeTLS("", "")
	} else {
		s.httpSrv.Handler = h2c.NewHandler(s.httpSrv.Handler, &http2.Server{})
		err = s.httpSrv.ListenAndServe()
	}
	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		corr := r.Header.Get("X-Correlation-Id")
		if corr == "" {
			corr = strconv.FormatInt(time.Now().UnixNano(), 36)
			r.Header.Set("X-Correlation-Id", corr)
		}
		w.Header().Set("X-Correlation-Id", corr)
		next.ServeHTTP(w, r)
	})
}

// handleUEContextTransfer serves Namf_Communication_UEContextTransfer (producer side).
// Ref: TS 29.518 §5.3.2.2.
func (s *Server) handleUEContextTransfer(w http.ResponseWriter, r *http.Request) {
	ueContextID := r.PathValue("ueContextId")
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	log := logging.NewProcedureLogger(ctx, s.logger, "UEContextTransfer").With(
		"interface", "Namf", "direction", "IN", "spec_ref", "TS 29.518 §5.3.2",
	)

	var req UeContextTransferReqData
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("malformed UEContextTransfer body", "result", "REJECT", "cause", "MANDATORY_IE_MISSING", "error", err)
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "invalid JSON body")
		metrics.ProcedureTotal.WithLabelValues(nfName, "UEContextTransfer", "REJECT").Inc()
		return
	}

	// reason is a mandatory IE. Ref: TS 29.518 §6.1.6.2.2.
	if req.Reason == "" {
		log.Warn("UEContextTransfer missing reason", "result", "REJECT", "cause", "MANDATORY_IE_MISSING")
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "reason is mandatory")
		metrics.ProcedureTotal.WithLabelValues(nfName, "UEContextTransfer", "REJECT").Inc()
		return
	}

	ue, found := s.lookupUE(ueContextID)
	if !found {
		log.Info("UEContextTransfer: UE context not found",
			"ue_context_id", ueContextID, "reason", req.Reason,
			"result", "REJECT", "cause", "CONTEXT_NOT_FOUND")
		s.problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "no UE context for the given identifier")
		metrics.ProcedureTotal.WithLabelValues(nfName, "UEContextTransfer", "REJECT").Inc()
		return
	}

	rsp := s.buildTransferRsp(ue)

	// Mark the context transferred but keep it until RegistrationStatusUpdate or
	// implicit detach. Ref: TS 23.502 §4.2.2.2.3.
	ue.Lock()
	ue.Transferred = true
	supi := ue.SUPI
	ue.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(rsp)

	log.Info("UE context transferred to new AMF",
		"supi", supi,
		"ue_context_id", ueContextID,
		"reason", req.Reason,
		"pdu_sessions", len(rsp.UeContext.SessionContextList),
		"result", "OK",
	)
	metrics.ProcedureTotal.WithLabelValues(nfName, "UEContextTransfer", "OK").Inc()
}

// handleN1N2MessageTransfer serves Namf_Communication_N1N2MessageTransfer (producer side).
// When the target UE is CM-IDLE it triggers NGAP Paging and returns 202; when the UE is
// CM-CONNECTED it acknowledges direct delivery with 200.
// Ref: TS 29.518 §5.2.2.3, TS 23.502 §4.2.3.3.
func (s *Server) handleN1N2MessageTransfer(w http.ResponseWriter, r *http.Request) {
	ueContextID := r.PathValue("ueContextId")
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	log := logging.NewProcedureLogger(ctx, s.logger, "NetworkTriggeredServiceRequest").With(
		"interface", "Namf", "direction", "IN", "spec_ref", "TS 23.502 §4.2.3.3",
	)

	var req N1N2MessageTransferReqData
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("malformed N1N2MessageTransfer body", "result", "REJECT", "cause", "MANDATORY_IE_MISSING", "error", err)
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "invalid JSON body")
		metrics.ProcedureTotal.WithLabelValues(nfName, "NetworkTriggeredServiceRequest", "REJECT").Inc()
		return
	}

	ue, found := s.lookupUE(ueContextID)
	if !found {
		log.Info("N1N2MessageTransfer: UE context not found",
			"ue_context_id", ueContextID, "result", "REJECT", "cause", "CONTEXT_NOT_FOUND")
		s.problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "no UE context for the given identifier")
		metrics.ProcedureTotal.WithLabelValues(nfName, "NetworkTriggeredServiceRequest", "REJECT").Inc()
		return
	}

	ue.Lock()
	connected := ue.CMState == amfctx.CMConnected
	supi := ue.SUPI
	ue.Unlock()

	var psi int = -1
	if req.PduSessionID != nil {
		psi = int(*req.PduSessionID)
	}

	if connected {
		// UE is reachable — the N1/N2 payload is delivered over the existing N2
		// connection (PDU session resource setup / DL NAS). Ref: TS 23.502 §4.2.3.3 (UE in CM-CONNECTED).
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(N1N2MessageTransferRspData{Cause: CauseN1N2TransferInitiated})
		log.Info("N1N2 message delivered to CM-CONNECTED UE",
			"supi", supi, "pdu_session_id", psi, "result", "OK", "cause", CauseN1N2TransferInitiated)
		metrics.ProcedureTotal.WithLabelValues(nfName, "NetworkTriggeredServiceRequest", "OK").Inc()
		return
	}

	// UE is CM-IDLE — trigger paging so it returns via Service Request.
	if s.pager != nil {
		if err := s.pager.SendPaging(ue); err != nil {
			log.Warn("paging trigger failed", "supi", supi, "error", err)
		}
	} else {
		log.Warn("no pager wired — cannot send NGAP Paging", "supi", supi)
	}
	ue.Lock()
	ue.PendingN1N2 = true
	ue.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(N1N2MessageTransferRspData{Cause: CauseAttemptingToReachUE})
	log.Info("CM-IDLE UE paged for network-triggered service request",
		"supi", supi, "pdu_session_id", psi, "result", "OK", "cause", CauseAttemptingToReachUE)
	metrics.ProcedureTotal.WithLabelValues(nfName, "NetworkTriggeredServiceRequest", "OK").Inc()
}

// handleProvideLocInfo serves Namf_Location_ProvideLocationInfo (producer side).
// It resolves the UE, verifies CM-CONNECTED, sends NGAP LocationReportingControl
// to the serving gNB, blocks until the LocationReport arrives (or times out),
// then returns LocationData with the NRCGI and TAI.
//
// Ref: TS 29.518 §5.2.2.6; TS 38.413 §8.17.1; TS 23.273 §7.2.
func (s *Server) handleProvideLocInfo(w http.ResponseWriter, r *http.Request) {
	ueContextID := r.PathValue("ueContextId")
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	corrID := logging.CorrelationID(ctx)
	log := logging.NewProcedureLogger(ctx, s.logger, "ProvideLocationInfo").With(
		"interface", "Namf",
		"direction", "IN",
		"spec_ref", "TS 29.518 §5.2.2.6",
		"correlation_id", corrID,
		"ue_context_id", ueContextID,
	)

	var req RequestLocInfo
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("malformed ProvideLocationInfo body",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING", "error", err)
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "invalid JSON body")
		metrics.ProcedureTotal.WithLabelValues(nfName, "ProvideLocationInfo", "REJECT").Inc()
		return
	}

	if !req.Req5gsLoc {
		log.Warn("req5gsLoc not set — mandatory for Cell-ID MVP",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING")
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "req5gsLoc must be true for Cell-ID positioning")
		metrics.ProcedureTotal.WithLabelValues(nfName, "ProvideLocationInfo", "REJECT").Inc()
		return
	}

	ue, found := s.lookupUE(ueContextID)
	if !found {
		log.Info("ProvideLocationInfo: UE context not found",
			"result", "REJECT", "cause", "CONTEXT_NOT_FOUND")
		s.problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "no UE context for the given identifier")
		metrics.ProcedureTotal.WithLabelValues(nfName, "ProvideLocationInfo", "REJECT").Inc()
		return
	}

	ue.Lock()
	connected := ue.CMState == amfctx.CMConnected
	supi := ue.SUPI
	amfID := ue.AMFUENGAPId
	ue.Unlock()

	log = log.With("supi", supi, "amf_ue_ngap_id", amfID)

	if !connected {
		// Paging-then-locate (Deferred MT Location, TS 23.273 §7.2 steps E2–E7):
		// trigger NGAP Paging, block until the UE returns to CM-CONNECTED via a
		// Service Request, then fall through to the NGAP location exchange below.
		if s.pager == nil {
			log.Error("ProvideLocationInfo: no Pager wired — cannot page CM-IDLE UE",
				"result", "FAILURE", "cause", CauseLocationFailure)
			s.problem(w, http.StatusServiceUnavailable, CauseLocationFailure,
				"internal: Pager not configured")
			metrics.ProcedureTotal.WithLabelValues(nfName, "ProvideLocationInfo", "FAILURE").Inc()
			return
		}
		pageCh := make(chan struct{}, 1)
		s.pendingLocPage.Store(amfID, pageCh)
		log.Info("ProvideLocationInfo: UE is CM-IDLE — triggering paging-then-locate",
			"direction", "OUT", "interface", "N2",
			"spec_ref", "TS 23.273 §7.2 steps E2-E7")
		if err := s.pager.SendPaging(ue); err != nil {
			s.pendingLocPage.Delete(amfID)
			log.Error("ProvideLocationInfo: paging failed", "error", err,
				"result", "FAILURE", "cause", CauseLocationFailure)
			s.problem(w, http.StatusGatewayTimeout, CauseLocationFailure,
				"paging failed: "+err.Error())
			metrics.ProcedureTotal.WithLabelValues(nfName, "ProvideLocationInfo", "FAILURE").Inc()
			return
		}
		pageCtx, pageCancel := context.WithTimeout(r.Context(), pageTimeout)
		defer pageCancel()
		select {
		case <-pageCh:
			log.Info("ProvideLocationInfo: paged UE returned to CM-CONNECTED — proceeding with location",
				"supi", supi, "spec_ref", "TS 23.273 §7.2 step E7")
		case <-pageCtx.Done():
			s.pendingLocPage.Delete(amfID)
			log.Warn("ProvideLocationInfo: UE did not respond to paging within T-positioning",
				"timeout_s", pageTimeout.Seconds(), "result", "FAILURE", "cause", CauseUENotReachable)
			s.problem(w, http.StatusGatewayTimeout, CauseUENotReachable,
				"UE did not respond to paging within T-positioning (15 s)")
			metrics.ProcedureTotal.WithLabelValues(nfName, "ProvideLocationInfo", "FAILURE").Inc()
			return
		}
		// UE is now CM-CONNECTED; fall through to NGAP LocationReportingControl.
	}

	if s.locator == nil {
		log.Error("ProvideLocationInfo: no Locator wired — cannot send NGAP LocationReportingControl",
			"result", "FAILURE", "cause", CauseLocationFailure)
		s.problem(w, http.StatusServiceUnavailable, CauseLocationFailure,
			"internal: Locator not configured")
		metrics.ProcedureTotal.WithLabelValues(nfName, "ProvideLocationInfo", "FAILURE").Inc()
		return
	}

	log.Info("sending NGAP LocationReportingControl to gNB",
		"direction", "OUT",
		"interface", "N2",
		"spec_ref", "TS 38.413 §8.17.1",
	)

	ch, err := s.locator.SendLocationReportingControl(ue)
	if err != nil {
		log.Error("SendLocationReportingControl failed",
			"result", "FAILURE", "cause", CauseLocationFailure, "error", err)
		s.problem(w, http.StatusGatewayTimeout, CauseLocationFailure,
			fmt.Sprintf("NGAP LocationReportingControl failed: %v", err))
		metrics.ProcedureTotal.WithLabelValues(nfName, "ProvideLocationInfo", "FAILURE").Inc()
		return
	}

	// Block until the gNB responds with a LocationReport or the deadline expires.
	// locationTimeout is the implementation-defined guard value; see constant doc.
	// Ref: TS 38.413 §8.17.1; TS 23.273 §7.2.
	locCtx, cancel := context.WithTimeout(ctx, locationTimeout)
	defer cancel()

	var result ngap.LocationResult
	select {
	case result = <-ch:
	case <-locCtx.Done():
		// Timeout: clean up the pending map entry so the handler doesn't fire later.
		// The channel was buffered(1) so if a late LocationReport arrives it will
		// send into the buffer without blocking (no goroutine leak).
		result = ngap.LocationResult{Err: fmt.Errorf("location timeout after %s", locationTimeout)}
	}

	if result.Err != nil {
		log.Warn("ProvideLocationInfo: NGAP location exchange failed",
			"result", "FAILURE", "cause", CauseLocationFailure, "error", result.Err)
		s.problem(w, http.StatusGatewayTimeout, CauseLocationFailure, result.Err.Error())
		metrics.ProcedureTotal.WithLabelValues(nfName, "ProvideLocationInfo", "FAILURE").Inc()
		return
	}

	// Build the response. TAI is optional in the ngap.LocationResult if the gNB
	// did not include UserLocationInformation; we include it when available.
	rsp := LocationData{
		LocationEstimate: &GeographicArea{
			Shape: "POINT",
			Point: &LatLon{Lat: 0, Lon: 0},
		},
		NRCellId:              result.NRCellID,
		AgeOfLocationEstimate: 0,
	}
	if result.TAI != nil {
		rsp.Tai = &TaiLoc{
			PlmnId: PlmnID{MCC: result.TAI.MCC, MNC: result.TAI.MNC},
			Tac:    fmt.Sprintf("%06x", result.TAI.TAC),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(rsp)

	log.Info("ProvideLocationInfo complete",
		"nr_cell_id", result.NRCellID,
		"result", "OK",
		"spec_ref", "TS 29.518 §5.2.2.6",
	)
	metrics.ProcedureTotal.WithLabelValues(nfName, "ProvideLocationInfo", "OK").Inc()
}

// handleDLNRPPaInfo serves Namf_Location dl-nrppa-info (producer side).
//
// The LMF sends a base64url-encoded NRPPa PDU in the request body. The AMF:
//  1. Resolves the UE (must be CM-CONNECTED).
//  2. Sends NGAP DownlinkUEAssociatedNRPPaTransport (ProcCode=8) to the serving gNB.
//  3. Blocks until the matching UplinkUEAssociatedNRPPaTransport arrives from the gNB
//     (keyed by AMF-UE-NGAP-ID via pendingNRPPa) or the nrppaTimeout expires.
//  4. Returns HTTP 200 with the UL NRPPa PDU base64url-encoded in the response body.
//
// The AMF is a pure relay — it MUST NOT decode the NRPPa-PDU bytes.
//
// Ref: TS 29.518 §5.2.2.6 (Namf_Location extension for NRPPa relay);
// TS 38.413 §8.17.3 (UE-associated NRPPa Transport);
// TS 23.273 §7.2 step C.
func (s *Server) handleDLNRPPaInfo(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ueContextID := r.PathValue("ueContextId")
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	corrID := logging.CorrelationID(ctx)
	log := logging.NewProcedureLogger(ctx, s.logger, "NRPPaRelay").With(
		"nf", "AMF",
		"procedure", "NRPPaRelay",
		"interface", "Namf",
		"direction", "IN",
		"spec_ref", "TS 38.413 §8.17.3",
		"correlation_id", corrID,
		"ue_context_id", ueContextID,
	)

	var req DLNRPPaInfoReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("dl-nrppa-info: malformed request body",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING", "error", err,
			"duration_ms", time.Since(start).Milliseconds())
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "invalid JSON body")
		metrics.ProcedureTotal.WithLabelValues(nfName, "NRPPaRelay", "REJECT").Inc()
		return
	}

	if req.NrppaPdu == "" {
		log.Warn("dl-nrppa-info: nrppaPdu missing",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING",
			"duration_ms", time.Since(start).Milliseconds())
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "nrppaPdu is mandatory")
		metrics.ProcedureTotal.WithLabelValues(nfName, "NRPPaRelay", "REJECT").Inc()
		return
	}

	nrppaPDU, err := base64.StdEncoding.DecodeString(req.NrppaPdu)
	if err != nil {
		// Try URL-safe encoding fallback.
		nrppaPDU, err = base64.URLEncoding.DecodeString(req.NrppaPdu)
		if err != nil {
			log.Warn("dl-nrppa-info: invalid base64 nrppaPdu",
				"result", "REJECT", "cause", "MANDATORY_IE_MISSING", "error", err,
				"duration_ms", time.Since(start).Milliseconds())
			s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "nrppaPdu: invalid base64")
			metrics.ProcedureTotal.WithLabelValues(nfName, "NRPPaRelay", "REJECT").Inc()
			return
		}
	}

	var routingID []byte
	if req.RoutingId != "" {
		routingID, _ = base64.StdEncoding.DecodeString(req.RoutingId)
		if routingID == nil {
			routingID, _ = base64.URLEncoding.DecodeString(req.RoutingId)
		}
	}

	ue, found := s.lookupUE(ueContextID)
	if !found {
		log.Info("dl-nrppa-info: UE context not found",
			"result", "REJECT", "cause", "CONTEXT_NOT_FOUND",
			"duration_ms", time.Since(start).Milliseconds())
		s.problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "no UE context for the given identifier")
		metrics.ProcedureTotal.WithLabelValues(nfName, "NRPPaRelay", "REJECT").Inc()
		return
	}

	ue.Lock()
	connected := ue.CMState == amfctx.CMConnected
	supi := ue.SUPI
	amfID := ue.AMFUENGAPId
	ue.Unlock()

	log = log.With("supi", supi, "amf_ue_ngap_id", amfID)

	if !connected {
		log.Warn("dl-nrppa-info: UE is not CM-CONNECTED — NRPPa relay requires active N2",
			"result", "FAILURE", "cause", CauseNRPPaRelayFailure,
			"duration_ms", time.Since(start).Milliseconds())
		s.problem(w, http.StatusGatewayTimeout, CauseNRPPaRelayFailure,
			"UE is CM-IDLE — NRPPa relay requires CM-CONNECTED")
		metrics.ProcedureTotal.WithLabelValues(nfName, "NRPPaRelay", "FAILURE").Inc()
		return
	}

	if s.nrppaRelay == nil {
		log.Error("dl-nrppa-info: no NRPPaRelay wired",
			"result", "FAILURE", "cause", CauseNRPPaRelayFailure,
			"duration_ms", time.Since(start).Milliseconds())
		s.problem(w, http.StatusServiceUnavailable, CauseNRPPaRelayFailure,
			"internal: NRPPaRelay not configured")
		metrics.ProcedureTotal.WithLabelValues(nfName, "NRPPaRelay", "FAILURE").Inc()
		return
	}

	log.Info("sending NGAP DownlinkUEAssociatedNRPPaTransport",
		"direction", "OUT",
		"interface", "N2",
		"nrppa_pdu_len", len(nrppaPDU),
		"spec_ref", "TS 38.413 §8.17.3",
	)

	ch, err := s.nrppaRelay.SendDownlinkNRPPa(ue, nrppaPDU, routingID)
	if err != nil {
		log.Error("dl-nrppa-info: SendDownlinkNRPPa failed",
			"result", "FAILURE", "cause", CauseNRPPaRelayFailure, "error", err,
			"duration_ms", time.Since(start).Milliseconds())
		s.problem(w, http.StatusGatewayTimeout, CauseNRPPaRelayFailure,
			fmt.Sprintf("NGAP DownlinkUEAssociatedNRPPaTransport failed: %v", err))
		metrics.ProcedureTotal.WithLabelValues(nfName, "NRPPaRelay", "FAILURE").Inc()
		return
	}

	// Block until the gNB responds with UplinkUEAssociatedNRPPaTransport or nrppaTimeout.
	// nrppaTimeout is an implementation-defined guard; TS 38.455 §8.2 has no normative timer
	// on the AMF side.
	nrppaCtx, cancel := context.WithTimeout(ctx, nrppaTimeout)
	defer cancel()

	var result ngap.NRPPaResult
	select {
	case result = <-ch:
	case <-nrppaCtx.Done():
		// Timeout: the channel is buffered(1); a late UL NRPPa will drain into the buffer
		// and not block the gNB handler goroutine (no goroutine leak).
		result = ngap.NRPPaResult{Err: fmt.Errorf("nrppa relay timeout after %s", nrppaTimeout)}
	}

	if result.Err != nil {
		log.Warn("dl-nrppa-info: NRPPa relay exchange failed",
			"result", "FAILURE", "cause", CauseNRPPaRelayFailure, "error", result.Err,
			"duration_ms", time.Since(start).Milliseconds())
		s.problem(w, http.StatusGatewayTimeout, CauseNRPPaRelayFailure, result.Err.Error())
		metrics.ProcedureTotal.WithLabelValues(nfName, "NRPPaRelay", "FAILURE").Inc()
		return
	}

	rsp := DLNRPPaInfoRsp{
		NrppaPdu: base64.StdEncoding.EncodeToString(result.NRPPaPDU),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(rsp)

	log.Info("dl-nrppa-info complete — UL NRPPa relayed to LMF",
		"ul_nrppa_pdu_len", len(result.NRPPaPDU),
		"result", "OK",
		"spec_ref", "TS 38.413 §8.17.3",
		"duration_ms", time.Since(start).Milliseconds(),
	)
	metrics.ProcedureTotal.WithLabelValues(nfName, "NRPPaRelay", "OK").Inc()
}

// handleDLLPPInfo serves Namf_Location dl-lpp-info (producer side, LMF-005).
//
// The LMF sends a base64-encoded opaque LPP-PDU in the request body. The AMF:
//  1. Resolves the UE (must be CM-CONNECTED — LPP needs an active N1/N2 path).
//  2. Wraps the LPP-PDU in a DL NAS Transport (payload container type 0x03)
//     and sends it to the UE (ciphered, SHT=0x02) via the LPPRelay.
//  3. Blocks until the matching UL NAS Transport (payload container type
//     0x03) arrives from the UE (keyed by AMF-UE-NGAP-ID via pendingLPP) or
//     lppTimeout expires.
//  4. Returns HTTP 200 with the UL LPP-PDU base64-encoded in the response body.
//
// The AMF is a pure relay — it MUST NOT decode the LPP-PDU bytes.
//
// Ref: TS 29.518 §5.2.2.6 (Namf_Location extension for LPP relay);
// TS 24.501 §8.7.4 / §9.11.3.40 (DL/UL NAS Transport, PCT=0x03);
// TS 23.273 §7.2 (AMF transparent relay); TS 37.355 §6.
func (s *Server) handleDLLPPInfo(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ueContextID := r.PathValue("ueContextId")
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	corrID := logging.CorrelationID(ctx)
	log := logging.NewProcedureLogger(ctx, s.logger, "LPPRelay").With(
		"nf", "AMF",
		"procedure", "LPPRelay",
		"interface", "Namf",
		"direction", "IN",
		"spec_ref", "TS 24.501 §8.7.4",
		"correlation_id", corrID,
		"ue_context_id", ueContextID,
	)

	var req DLLPPInfoReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("dl-lpp-info: malformed request body",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING", "error", err,
			"duration_ms", time.Since(start).Milliseconds())
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "invalid JSON body")
		metrics.ProcedureTotal.WithLabelValues(nfName, "LPPRelay", "REJECT").Inc()
		return
	}

	if req.LppPdu == "" {
		log.Warn("dl-lpp-info: lppPdu missing",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING",
			"duration_ms", time.Since(start).Milliseconds())
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "lppPdu is mandatory")
		metrics.ProcedureTotal.WithLabelValues(nfName, "LPPRelay", "REJECT").Inc()
		return
	}

	lppPDU, err := base64.StdEncoding.DecodeString(req.LppPdu)
	if err != nil {
		// Try URL-safe encoding fallback.
		lppPDU, err = base64.URLEncoding.DecodeString(req.LppPdu)
		if err != nil {
			log.Warn("dl-lpp-info: invalid base64 lppPdu",
				"result", "REJECT", "cause", "MANDATORY_IE_MISSING", "error", err,
				"duration_ms", time.Since(start).Milliseconds())
			s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "lppPdu: invalid base64")
			metrics.ProcedureTotal.WithLabelValues(nfName, "LPPRelay", "REJECT").Inc()
			return
		}
	}

	ue, found := s.lookupUE(ueContextID)
	if !found {
		log.Info("dl-lpp-info: UE context not found",
			"result", "REJECT", "cause", "CONTEXT_NOT_FOUND",
			"duration_ms", time.Since(start).Milliseconds())
		s.problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND", "no UE context for the given identifier")
		metrics.ProcedureTotal.WithLabelValues(nfName, "LPPRelay", "REJECT").Inc()
		return
	}

	ue.Lock()
	connected := ue.CMState == amfctx.CMConnected
	supi := ue.SUPI
	amfID := ue.AMFUENGAPId
	ue.Unlock()

	log = log.With("supi", supi, "amf_ue_ngap_id", amfID)

	if !connected {
		log.Warn("dl-lpp-info: UE is not CM-CONNECTED — LPP relay requires active N1/N2",
			"result", "FAILURE", "cause", CauseLPPRelayFailure,
			"duration_ms", time.Since(start).Milliseconds())
		s.problem(w, http.StatusGatewayTimeout, CauseLPPRelayFailure,
			"UE is CM-IDLE — LPP relay requires CM-CONNECTED")
		metrics.ProcedureTotal.WithLabelValues(nfName, "LPPRelay", "FAILURE").Inc()
		return
	}

	if s.lppRelay == nil {
		log.Error("dl-lpp-info: no LPPRelay wired",
			"result", "FAILURE", "cause", CauseLPPRelayFailure,
			"duration_ms", time.Since(start).Milliseconds())
		s.problem(w, http.StatusServiceUnavailable, CauseLPPRelayFailure,
			"internal: LPPRelay not configured")
		metrics.ProcedureTotal.WithLabelValues(nfName, "LPPRelay", "FAILURE").Inc()
		return
	}

	// expectUlResponse (ADDITIVE, LMF-009): absent/nil defaults to true
	// (LMF-005 synchronous behaviour, unchanged).
	expectUL := req.ExpectUlResponse == nil || *req.ExpectUlResponse

	log.Info("sending DL NAS Transport (LPP)",
		"direction", "OUT",
		"interface", "N1",
		"lpp_pdu_len", len(lppPDU),
		"expect_ul_response", expectUL,
		"spec_ref", "TS 24.501 §8.7.4",
	)

	if !expectUL {
		// DL-only leg (ProvideAssistanceData — TS 37.355 assistance-data
		// delivery is unsolicited, no response message): send the DL NAS
		// Transport, register NO pendingLPP waiter, return 204 No Content.
		// Ref: docs/procedures/LPPRelay.md §Endpoints; TS 37.355 §6.5.2.
		if err := s.lppRelay.SendDownlinkLPPNoWait(ue, lppPDU); err != nil {
			log.Error("dl-lpp-info: SendDownlinkLPPNoWait failed",
				"result", "FAILURE", "cause", CauseLPPRelayFailure, "error", err,
				"duration_ms", time.Since(start).Milliseconds())
			s.problem(w, http.StatusGatewayTimeout, CauseLPPRelayFailure,
				fmt.Sprintf("DL NAS Transport (LPP, no-wait) failed: %v", err))
			metrics.ProcedureTotal.WithLabelValues(nfName, "LPPRelay", "FAILURE").Inc()
			return
		}
		w.WriteHeader(http.StatusNoContent)
		log.Info("dl-lpp-info complete — DL-only leg sent (204, no pendingLPP waiter)",
			"result", "OK",
			"spec_ref", "TS 24.501 §8.7.4 / TS 37.355 §6.5.2",
			"duration_ms", time.Since(start).Milliseconds(),
		)
		metrics.ProcedureTotal.WithLabelValues(nfName, "LPPRelay", "OK").Inc()
		return
	}

	ch, err := s.lppRelay.SendDownlinkLPP(ue, lppPDU)
	if err != nil {
		log.Error("dl-lpp-info: SendDownlinkLPP failed",
			"result", "FAILURE", "cause", CauseLPPRelayFailure, "error", err,
			"duration_ms", time.Since(start).Milliseconds())
		s.problem(w, http.StatusGatewayTimeout, CauseLPPRelayFailure,
			fmt.Sprintf("DL NAS Transport (LPP) failed: %v", err))
		metrics.ProcedureTotal.WithLabelValues(nfName, "LPPRelay", "FAILURE").Inc()
		return
	}

	// Block until the UE responds with a UL NAS Transport (PCT=0x03) or lppTimeout.
	// lppTimeout is an implementation-defined guard; TS 23.273 §7.2 has no
	// normative timer for the LPP relay path.
	lppCtx, cancel := context.WithTimeout(ctx, lppTimeout)
	defer cancel()

	var result nasmsg.LPPResult
	select {
	case result = <-ch:
	case <-lppCtx.Done():
		// Timeout: the channel is buffered(1); a late UL LPP will drain into
		// the buffer and not block the NAS handler goroutine (no leak).
		result = nasmsg.LPPResult{Err: fmt.Errorf("lpp relay timeout after %s", lppTimeout)}
	}

	if result.Err != nil {
		log.Warn("dl-lpp-info: LPP relay exchange failed",
			"result", "FAILURE", "cause", CauseLPPRelayFailure, "error", result.Err,
			"duration_ms", time.Since(start).Milliseconds())
		s.problem(w, http.StatusGatewayTimeout, CauseLPPRelayFailure, result.Err.Error())
		metrics.ProcedureTotal.WithLabelValues(nfName, "LPPRelay", "FAILURE").Inc()
		return
	}

	rsp := DLLPPInfoRsp{
		LppPdu: base64.StdEncoding.EncodeToString(result.LPPPDU),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(rsp)

	log.Info("dl-lpp-info complete — UL LPP relayed to LMF",
		"ul_lpp_pdu_len", len(result.LPPPDU),
		"result", "OK",
		"spec_ref", "TS 24.501 §8.7.4",
		"duration_ms", time.Since(start).Milliseconds(),
	)
	metrics.ProcedureTotal.WithLabelValues(nfName, "LPPRelay", "OK").Inc()
}

// buildTransferRsp assembles the UeContextTransferRspData from the UE context.
func (s *Server) buildTransferRsp(ue *amfctx.UEContext) UeContextTransferRspData {
	ue.Lock()
	defer ue.Unlock()

	uc := UeContext{
		Supi: ue.SUPI,
		Pei:  ue.PEI,
	}

	if sc := ue.SecurityCtx; sc.Active {
		mm := MmContext{
			AccessType: "3GPP_ACCESS",
			NasSecurityMode: &NasSecurityMode{
				IntegrityAlgorithm: nasIntegName(sc.IntegrityAlgID),
				CipheringAlgorithm: nasCipherName(sc.CipheringAlgID),
			},
			NasDownlinkCount: sc.DownlinkCount,
			NasUplinkCount:   sc.UplinkCount,
		}
		if len(sc.KAMF) > 0 {
			mm.KAmf = base64.StdEncoding.EncodeToString(sc.KAMF)
		}
		if len(ue.RawUESecCap) > 0 {
			mm.UeSecurityCapability = base64.StdEncoding.EncodeToString(ue.RawUESecCap)
		}
		uc.MmContextList = append(uc.MmContextList, mm)
	}

	for psi, sess := range ue.PDUSessions {
		pc := PduSessionContext{
			PduSessionID:  psi,
			SmContextRef:  sess.SMFInstanceID,
			Dnn:           sess.DNN,
			AccessType:    "3GPP_ACCESS",
			SmfInstanceID: sess.SMFInstanceID,
			SNssai: &Snssai{
				Sst: sess.SNSSAI.SST,
				Sd:  sess.SNSSAI.SD,
			},
		}
		uc.SessionContextList = append(uc.SessionContextList, pc)
	}

	if ue.PolicyAssociationID != "" {
		uc.PcfID = ue.PolicyAssociationID
	}

	return UeContextTransferRspData{UeContext: uc}
}

// lookupUE resolves the ueContextId path parameter to a UE context.
// The new AMF may pass the 5G-GUTI ("5g-guti-<…>") the UE presented, or — where
// known — the SUPI ("imsi-<digits>"). We try SUPI first, then GUTI/TMSI.
// Ref: TS 29.518 §6.1.6.3 (ueContextId).
func (s *Server) lookupUE(id string) (*amfctx.UEContext, bool) {
	if id == "" {
		return nil, false
	}
	// SUPI form: "imsi-<digits>" or "suci-…" used verbatim as the SUPI key.
	if strings.HasPrefix(id, "imsi-") || strings.HasPrefix(id, "nai-") {
		if ue, ok := s.mgr.GetBySUPI(id); ok {
			return ue, true
		}
	}
	// GUTI form: "5g-guti-<…>" — the trailing 8 hex digits are the 5G-TMSI.
	if strings.HasPrefix(id, "5g-guti-") {
		hexTMSI := id[len(id)-8:]
		if tmsi, err := strconv.ParseUint(hexTMSI, 16, 32); err == nil {
			if ue, ok := s.mgr.GetByTMSI(uint32(tmsi)); ok {
				return ue, true
			}
		}
	}
	// Last resort: treat the whole id as a SUPI key.
	if ue, ok := s.mgr.GetBySUPI(id); ok {
		return ue, true
	}
	return nil, false
}

// problem writes an RFC 7807 ProblemDetails response.
func (s *Server) problem(w http.ResponseWriter, status int, cause, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ProblemDetails{
		Status: status,
		Cause:  cause,
		Detail: detail,
		Title:  http.StatusText(status),
	})
}

// loadTLSConfig builds the mTLS server config (HTTP/2, h2 ALPN). Returns nil
// when no cert/key is configured so the caller falls back to H2C (dev only).
// Ref: TS 29.500 §4.4, TS 33.501 §13.
func loadTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	}
	if caFile != "" {
		caData, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("no certs found in CA file %s", caFile)
		}
		// Mutual TLS — verify the client (new AMF) certificate. TS 33.501 §13.
		tlsCfg.ClientCAs = caPool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsCfg, nil
}
