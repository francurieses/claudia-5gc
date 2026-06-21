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
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
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

// Server is the AMF inbound SBI server (namf-comm).
// Ref: TS 29.518 §5.3.2.
type Server struct {
	cfg     Config
	mgr     *amfctx.Manager
	logger  *slog.Logger
	httpSrv *http.Server
	pager   Pager
}

// SetPager wires the NGAP paging trigger used by N1N2MessageTransfer.
func (s *Server) SetPager(p Pager) { s.pager = p }

// New builds the inbound SBI server. It does not start listening — call Start.
func New(cfg Config, mgr *amfctx.Manager, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{cfg: cfg, mgr: mgr, logger: logger}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /namf-comm/v1/ue-contexts/{ueContextId}/transfer", s.handleUEContextTransfer)
	mux.HandleFunc("POST /namf-comm/v1/ue-contexts/{ueContextId}/n1-n2-messages", s.handleN1N2MessageTransfer)
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
