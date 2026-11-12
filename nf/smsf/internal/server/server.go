// Package server implements the Nsmsf_SMService SBI server for the SMSF.
//
// Endpoints (3GPP TS 29.540 v17):
//
//	PUT    /nsmsf-sms/v2/ue-contexts/{supiOrGpsi}            Nsmsf_SMService_Activate
//	DELETE /nsmsf-sms/v2/ue-contexts/{supiOrGpsi}            Nsmsf_SMService_Deactivate
//	POST   /nsmsf-sms/v2/ue-contexts/{supiOrGpsi}/sendsms    Nsmsf_SMService_UplinkSMS
//	POST   /nsmsf-sms-internal/v1/ue-contexts/{supi}/mt-sms  Internal MT SMS trigger
//	GET    /healthz                                           Liveness probe
//	GET    /metrics                                           Prometheus metrics
//
// Ref: TS 29.540 §5.2
package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/francurieses/claudia-5gc/nf/smsf/internal/config"
	smsfctx "github.com/francurieses/claudia-5gc/nf/smsf/internal/context"
	smsfsbi "github.com/francurieses/claudia-5gc/nf/smsf/internal/sbi"
	"github.com/francurieses/claudia-5gc/shared/capability"
	"github.com/francurieses/claudia-5gc/shared/logging"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/sbi"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// AMFClient is the interface for delivering MT SMS to the AMF via
// Namf_Communication_N1N2MessageTransfer.
// Ref: TS 29.518 §5.2.2.3
type AMFClient interface {
	// SendN1N2Message posts an MT SMS N1N2 message transfer to the AMF callback URI.
	// smsPayload is the raw SM-CP/RP octet payload (same bytes the UE sent in UplinkSMS).
	SendN1N2Message(ctx context.Context, callbackURI, supi string, smsPayload []byte) error
}

// UDMClient is the interface for registering the SMSF at UDM on Activate.
// Ref: TS 29.503 §5.3.2 (Nudm_UECM_SMSFRegistration)
type UDMClient interface {
	// RegisterSMSF registers this SMSF for the given SUPI at the UDM UECM resource.
	RegisterSMSF(ctx context.Context, supi, smsfInstanceID string) error
}

// Server is the SMSF Nsmsf_SMService SBI server.
type Server struct {
	cfg       *config.Config
	logger    *slog.Logger
	store     *smsfctx.Store
	amfClient AMFClient
	udmClient UDMClient
	httpSrv   *http.Server

	// profile gates the supportedFeatures wire behaviour (decisions D1/D2,
	// dev/REL19_PROGRAM.md §2); nil behaves as rel17.
	profile *capability.Profile
	// cat is the Nsmsf_SMService producer catalog.
	cat *features.Catalog
}

// SetProfile wires the release profile used for supportedFeatures negotiation.
// Must be called before Start(). Ref: TS 29.500 §6.6.2.
func (s *Server) SetProfile(p *capability.Profile) { s.profile = p }

// SetCatalog replaces the Nsmsf_SMService catalog (tests inject catalogs with
// Implemented entries); nil restores the default. Must be called before Start().
func (s *Server) SetCatalog(c *features.Catalog) {
	if c == nil {
		c = smsfsbi.NsmsfSMServiceCatalog()
	}
	s.cat = c
}

// New constructs the SMSF SBI server. The server is not started until Start or
// ServeH2C is called. amfClient and udmClient may be nil (fail-open / log).
func New(cfg *config.Config, logger *slog.Logger) *Server {
	s := &Server{
		cfg:    cfg,
		logger: logger,
		store:  smsfctx.NewStore(),
		cat:    smsfsbi.NsmsfSMServiceCatalog(),
	}

	mux := http.NewServeMux()
	// Nsmsf_SMService routes (TS 29.540 §5.2)
	mux.HandleFunc("PUT /nsmsf-sms/v2/ue-contexts/{supiOrGpsi}", s.handleActivate)
	mux.HandleFunc("DELETE /nsmsf-sms/v2/ue-contexts/{supiOrGpsi}", s.handleDeactivate)
	mux.HandleFunc("POST /nsmsf-sms/v2/ue-contexts/{supiOrGpsi}/sendsms", s.handleUplinkSMS)
	// Internal MT SMS trigger endpoint (not in 3GPP TS 29.540 — internal convenience).
	// Used by the orchestrator / tests to originate an MT SMS without a real SMS-GMSC.
	mux.HandleFunc("POST /nsmsf-sms-internal/v1/ue-contexts/{supi}/mt-sms", s.handleMTSMSTrigger)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.Handle("GET /metrics", promhttp.Handler())

	s.httpSrv = &http.Server{
		Addr:              cfg.SBI.Address,
		Handler:           s.middleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s
}

// WithAMFClient sets the AMF client used to deliver MT SMS / MO acks.
// Call before Start. If never called, MT delivery is logged as FAILURE (fail-open).
func (s *Server) WithAMFClient(c AMFClient) *Server {
	s.amfClient = c
	return s
}

// WithUDMClient sets the UDM client used for UECM registration on Activate.
// Call before Start. If never called, UDM registration is skipped with a warning.
func (s *Server) WithUDMClient(c UDMClient) *Server {
	s.udmClient = c
	return s
}

// Handler returns the HTTP handler for in-process testing (no TLS / h2c).
// This is the test seam: drive the server with httptest.NewServer(srv.Handler()).
func (s *Server) Handler() http.Handler { return s.httpSrv.Handler }

// Start starts the SBI server. If TLS cert/key are configured, it listens
// with mTLS + HTTP/2 (h2 ALPN). Otherwise it falls back to plain h2c.
//
// ALPN invariant: TLSConfig.NextProtos = ["h2"] is set BEFORE ConfigureServer.
// Ref: TS 29.500 §4.4.2 — SBA always mTLS.
func (s *Server) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpSrv.Shutdown(shutCtx)
	}()

	if s.cfg.SBI.TLS.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.SBI.TLS.CertFile, s.cfg.SBI.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("smsf: server: load TLS cert: %w", err)
		}
		caPEM, err := os.ReadFile(s.cfg.SBI.TLS.CAFile)
		if err != nil {
			return fmt.Errorf("smsf: server: load CA: %w", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caPEM)

		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    pool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS13,
			// NextProtos MUST be set before ConfigureServer (ALPN invariant).
			// Ref: docs/memory/http2_alpn_conformance.md
			NextProtos: []string{"h2"},
		}
		s.httpSrv.TLSConfig = tlsCfg
		if err := http2.ConfigureServer(s.httpSrv, &http2.Server{}); err != nil {
			return fmt.Errorf("smsf: server: configure http2: %w", err)
		}
		s.logger.Info("SMSF SBI listening (mTLS + HTTP/2)",
			"addr", s.cfg.SBI.Address,
			"service", "nsmsf-sms",
			"spec_ref", "TS 29.540 §5.2",
		)
		if err := s.httpSrv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("smsf: server: listen: %w", err)
		}
		return nil
	}

	// No TLS — use h2c for in-process functional tests.
	s.httpSrv.Handler = h2c.NewHandler(s.httpSrv.Handler, &http2.Server{})
	s.logger.Info("SMSF SBI listening (plain h2c — no TLS configured)",
		"addr", s.cfg.SBI.Address,
		"service", "nsmsf-sms",
	)
	if err := s.httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("smsf: server: listen: %w", err)
	}
	return nil
}

// ServeH2C starts the server on the given pre-bound listener using plain HTTP/2 (h2c).
// Intended for in-process functional tests that bind their own listener.
func (s *Server) ServeH2C(ln net.Listener) error {
	h2Srv := &http2.Server{}
	handler := h2c.NewHandler(s.httpSrv.Handler, h2Srv)
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	return srv.Serve(ln)
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

// ---- middleware -------------------------------------------------------------

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

// ---- Activate --------------------------------------------------------------

// activateRequest is the body of PUT /nsmsf-sms/v2/ue-contexts/{supiOrGpsi}.
// Ref: TS 29.540 §6.1.6.2.2 (UeSmsContextData)
//
// oapi: TS29540_Nsmsf_SMService.yaml#/components/schemas/UeSmsContextData
type activateRequest struct {
	Supi       string `json:"supi"`
	Gpsi       string `json:"gpsi,omitempty"`
	Pei        string `json:"pei,omitempty"`
	AmfID      string `json:"amfId"`
	AccessType string `json:"accessType"`
	// AmfCallbackURI is where the SMSF delivers MT SMS (N1N2MessageTransfer).
	// oapi-ext: UeSmsContextData carries no AMF endpoint (amfId only, TS 29.540 §6.1.6.2.2); a spec SMSF resolves the AMF through NRF discovery with amfId. Sent by this project's AMF; a third-party AMF omits it.
	AmfCallbackURI string `json:"amfCallbackUri,omitempty"`
	// SupportedFeatures: TS 29.540 §6.1.6.2.2 (UeSmsContextData), negotiated
	// per TS 29.500 §6.6.2 against Table 6.1.8-1.
	SupportedFeatures string `json:"supportedFeatures,omitempty"`
}

// handleActivate implements Nsmsf_SMService_Activate.
// PUT /nsmsf-sms/v2/ue-contexts/{supiOrGpsi} (OpenAPI operationId SMServiceActivation)
// Ref: TS 29.540 §5.2.2
func (s *Server) handleActivate(w http.ResponseWriter, r *http.Request) {
	supiOrGpsi := r.PathValue("supiOrGpsi")
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	log := logging.NewProcedureLogger(ctx, s.logger, "SmsActivate").With(
		"nf", "SMSF",
		"interface", "Nsmsf",
		"direction", "IN",
		"spec_ref", "TS 29.540 §5.2.2",
		"supi", supiOrGpsi,
	)

	peerNF := features.PeerNFTypeFromUserAgent(r.UserAgent(), "AMF")
	var req activateRequest
	r.Body = http.MaxBytesReader(w, r.Body, features.MaxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if features.IsTypeError(err) {
			s.rejectSupportedFeatures(ctx, w, peerNF, "<non-string>", err)
			return
		}
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			payloadTooLarge(log, w, "SmsActivate")
			return
		}
		log.Warn("Activate: malformed request body",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING", "error", err)
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "invalid JSON body")
		return
	}

	// supportedFeatures must be schema-valid before any state is touched.
	// Ref: TS 29.500 §5.2.7.2, §6.6.2.
	if err := features.Validate(req.SupportedFeatures); err != nil {
		s.rejectSupportedFeatures(ctx, w, peerNF, req.SupportedFeatures, err)
		return
	}
	// Producer side (decision D1): the intersection, absent under rel17 when
	// the request had none, "0" under rel19.
	sfAnswer, sfSet := features.Answer(s.cat, s.profile, req.SupportedFeatures)

	// Validate mandatory IEs (TS 29.540 §6.1.6.2.2)
	// supi in body is mandatory when supiOrGpsi path param is not a SUPI.
	// We require supi explicitly in the body (it must not be empty).
	if req.Supi == "" {
		log.Warn("Activate: missing mandatory IE supi",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING")
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "supi is mandatory in request body")
		return
	}
	if req.AccessType == "" {
		log.Warn("Activate: missing mandatory IE accessType",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING", "supi", req.Supi)
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "accessType is mandatory")
		return
	}

	// Build the UE SMS context.
	uectx := &smsfctx.UESMSContext{
		SUPI:           req.Supi,
		GPSI:           req.Gpsi,
		PEI:            req.Pei,
		AmfID:          req.AmfID,
		AccessType:     req.AccessType,
		AmfCallbackURI: req.AmfCallbackURI,
		State:          smsfctx.StateActive,
		Features:       sfSet,
	}
	s.store.Set(supiOrGpsi, uectx)
	// Also store under the explicit SUPI if the path key is different.
	if req.Supi != supiOrGpsi {
		s.store.Set(req.Supi, uectx)
	}

	// Register SMSF at UDM (Nudm_UECM_SMSFRegistration).
	// Non-fatal: if UDM is unavailable, we log and continue.
	// Ref: TS 29.540 §5.2.2 step 3 / TS 29.503 §5.3.2
	if s.udmClient != nil {
		if err := s.udmClient.RegisterSMSF(ctx, req.Supi, s.cfg.NFInstanceID); err != nil {
			log.Warn("Activate: UDM UECM registration failed (continuing)",
				"supi", req.Supi, "error", err,
				"interface", "N21", "direction", "OUT",
				"spec_ref", "TS 29.503 §5.3.2",
			)
		} else {
			log.Info("Activate: UDM UECM registration complete",
				"supi", req.Supi,
				"interface", "N21", "direction", "OUT",
				"spec_ref", "TS 29.503 §5.3.2",
			)
		}
	} else {
		log.Warn("Activate: UDM client not configured — skipping UECM registration",
			"supi", req.Supi)
	}

	// Request accepted: record the negotiation (TS 29.500 §6.6.2).
	features.LogNegotiation(ctx, s.logger, features.Negotiation{
		NF:        "SMSF",
		Interface: "Nsmsf", Direction: "IN", PeerNF: peerNF,
		SpecRef: features.SpecRef, Result: "OK",
		Local: s.cat.Supported(s.profile), Peer: req.SupportedFeatures,
		PeerPresent: req.SupportedFeatures != "", Negotiated: sfSet,
	})

	log.Info("SMS context activated",
		"supi", req.Supi,
		"access_type", req.AccessType,
		"amf_id", req.AmfID,
		"result", "OK",
	)

	// 201 Created + UeSmsContextData echo.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location",
		"/nsmsf-sms/v2/ue-contexts/"+supiOrGpsi)
	w.WriteHeader(http.StatusCreated)
	rsp := map[string]any{
		"supi":       req.Supi,
		"accessType": req.AccessType,
		"amfId":      req.AmfID,
	}
	if sfAnswer != "" {
		rsp["supportedFeatures"] = sfAnswer
	}
	_ = json.NewEncoder(w).Encode(rsp)
}

// rejectSupportedFeatures answers a schema-invalid supportedFeatures with 400
// INVALID_MSG_FORMAT and invalidParams[{param: /supportedFeatures}] and logs
// the REJECT negotiation record. Ref: TS 29.500 §5.2.7.2; TS 29.571 §5.2.4.6.
func (s *Server) rejectSupportedFeatures(ctx context.Context, w http.ResponseWriter, peerNF, shown string, cause error) {
	features.LogNegotiation(ctx, s.logger, features.Negotiation{
		NF:        "SMSF",
		Interface: "Nsmsf", Direction: "IN", PeerNF: peerNF,
		SpecRef: features.SpecRefInvalid, Result: "REJECT", Cause: features.CauseInvalidMsgFormat,
		Local: s.cat.Supported(s.profile), Peer: shown, PeerPresent: true,
	}, "error", cause)
	metrics.ProcedureTotal.WithLabelValues("SMSF", "SmsActivate", "REJECT").Inc()
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": http.StatusBadRequest,
		"cause":  features.CauseInvalidMsgFormat,
		"detail": "supportedFeatures is not a valid hexadecimal string",
		"invalidParams": []map[string]string{
			{"param": features.ParamSupportedFeatures},
		},
	})
}

// payloadTooLarge answers a body over features.MaxRequestBodyBytes with 413 and
// a ProblemDetails without a cause (no 413 cause is defined), after logging one
// REJECT record and counting it under the given procedure label.
// Ref: TS 29.500 §5.2.7.1; TS 29.571 §5.2.4.1.
func payloadTooLarge(log *slog.Logger, w http.ResponseWriter, procedure string) {
	log.Warn("request body too large",
		"result", "REJECT", "cause", "PAYLOAD_TOO_LARGE")
	metrics.ProcedureTotal.WithLabelValues("SMSF", procedure, "REJECT").Inc()
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusRequestEntityTooLarge)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": http.StatusRequestEntityTooLarge,
		"detail": "request body too large",
	})
}

// ---- Deactivate ------------------------------------------------------------

// handleDeactivate implements Nsmsf_SMService_Deactivate.
// DELETE /nsmsf-sms/v2/ue-contexts/{supiOrGpsi}
// Ref: TS 29.540 §5.2.3
func (s *Server) handleDeactivate(w http.ResponseWriter, r *http.Request) {
	supiOrGpsi := r.PathValue("supiOrGpsi")
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	log := logging.NewProcedureLogger(ctx, s.logger, "SmsDeactivate").With(
		"nf", "SMSF",
		"interface", "Nsmsf",
		"direction", "IN",
		"spec_ref", "TS 29.540 §5.2.3",
		"supi", supiOrGpsi,
	)

	found := s.store.Delete(supiOrGpsi)
	if !found {
		log.Warn("Deactivate: context not found",
			"result", "REJECT", "cause", "CONTEXT_NOT_FOUND")
		s.problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND",
			"no active SMS context for "+supiOrGpsi)
		return
	}

	log.Info("SMS context deactivated", "result", "OK")
	w.WriteHeader(http.StatusNoContent)
}

// ---- UplinkSMS (MO SMS) ----------------------------------------------------

// uplinkSMSRequest is the legacy Rel-17-profile JSON body of
// POST /nsmsf-sms/v2/ue-contexts/{supiOrGpsi}/sendsms (smsPayload inline base64).
// Still accepted whatever the SMSF profile.
//
// oapi: none legacy Rel-17-profile wire shape of SmsRecordData, see uplinkSMSRecordData
type uplinkSMSRequest struct {
	// SmsPayload is the base64-encoded SM-CP/RP payload extracted from the NAS
	// Payload Container (Payload Container Type = SMS, 0x02).
	SmsPayload  string `json:"smsPayload"`
	SmsRecordId string `json:"smsRecordId"`
}

// uplinkSMSRecordData is the JSON root part of the spec-literal multipart/related
// UplinkSMS request: smsPayload is a RefToBinaryData naming the binary part.
// Ref: TS 29.540 §6.1.6.2.3 (SmsRecordData), TS 29.571 §5.2.2 (RefToBinaryData)
//
// oapi: TS29540_Nsmsf_SMService.yaml#/components/schemas/SmsRecordData
type uplinkSMSRecordData struct {
	SmsRecordId string          `json:"smsRecordId"`
	SmsPayload  refToBinaryData `json:"smsPayload"`
}

// refToBinaryData references a binary body part by its Content-Id.
//
// oapi: TS29571_CommonData.yaml#/components/schemas/RefToBinaryData
type refToBinaryData struct {
	ContentId string `json:"contentId"`
}

// errUplinkMultipart is a client-visible multipart/related decoding error
// carrying the ProblemDetails cause and the offending attribute pointer.
type errUplinkMultipart struct {
	cause  string // TS 29.500 Table 5.2.7.2-1 application error cause
	param  string // invalidParams[].param, empty when none applies
	detail string
}

func (e *errUplinkMultipart) Error() string { return e.detail }

// parseUplinkMultipart extracts (smsRecordId, base64 payload) from a
// multipart/related UplinkSMS request: the JSON root part (the part named by the
// "start" parameter, else the first) and the binary part whose Content-Id
// equals smsPayload.contentId. Body-read errors (*http.MaxBytesError) and
// oversized parts (sbi.ErrRelatedPartTooLarge) are returned for a 413.
// Causes follow TS 29.500 Table 5.2.7.2-1: malformed message / bad JSON root ->
// INVALID_MSG_FORMAT; missing contentId -> MANDATORY_IE_MISSING; unmatched
// contentId or empty binary part -> MANDATORY_IE_INCORRECT.
// Ref: TS 29.540 §5.2.4, TS 29.500 §5.4, §5.2.7.2
func parseUplinkMultipart(contentType string, body io.Reader) (recordID, payloadB64 string, err error) {
	parts, derr := sbi.DecodeRelated(contentType, body)
	if derr != nil {
		var mbe *http.MaxBytesError
		if errors.As(derr, &mbe) || errors.Is(derr, sbi.ErrRelatedPartTooLarge) {
			return "", "", derr
		}
		return "", "", &errUplinkMultipart{cause: features.CauseInvalidMsgFormat, detail: "invalid multipart/related body: " + derr.Error()}
	}
	if len(parts) == 0 {
		return "", "", &errUplinkMultipart{cause: features.CauseInvalidMsgFormat, detail: "multipart/related body has no parts"}
	}
	if mt, _, perr := mime.ParseMediaType(parts[0].ContentType); perr != nil || mt != "application/json" {
		return "", "", &errUplinkMultipart{cause: features.CauseInvalidMsgFormat, detail: "root part Content-Type is not application/json"}
	}
	var rec uplinkSMSRecordData
	if jerr := json.Unmarshal(parts[0].Body, &rec); jerr != nil {
		return "", "", &errUplinkMultipart{cause: features.CauseInvalidMsgFormat, detail: "invalid JSON root part"}
	}
	if rec.SmsPayload.ContentId == "" {
		return "", "", &errUplinkMultipart{cause: "MANDATORY_IE_MISSING", param: "/smsPayload/contentId", detail: "smsPayload.contentId missing"}
	}
	for _, p := range parts[1:] {
		if p.ContentID == rec.SmsPayload.ContentId {
			if len(p.Body) == 0 {
				return "", "", &errUplinkMultipart{cause: "MANDATORY_IE_INCORRECT", param: "/smsPayload/contentId", detail: "SMS binary part is empty"}
			}
			return rec.SmsRecordId, base64.StdEncoding.EncodeToString(p.Body), nil
		}
	}
	return "", "", &errUplinkMultipart{cause: "MANDATORY_IE_INCORRECT", param: "/smsPayload/contentId", detail: "no body part with Content-Id " + rec.SmsPayload.ContentId}
}

// handleUplinkSMS implements Nsmsf_SMService_UplinkSMS.
// POST /nsmsf-sms/v2/ue-contexts/{supiOrGpsi}/sendsms
// Ref: TS 29.540 §5.2.4
func (s *Server) handleUplinkSMS(w http.ResponseWriter, r *http.Request) {
	supiOrGpsi := r.PathValue("supiOrGpsi")
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	log := logging.NewProcedureLogger(ctx, s.logger, "SmsOverNas").With(
		"nf", "SMSF",
		"procedure", "UplinkSMS",
		"interface", "Nsmsf",
		"direction", "IN",
		"spec_ref", "TS 29.540 §5.2.4",
		"supi", supiOrGpsi,
	)

	// Context must exist (Activate must have been called first).
	uectx, ok := s.store.Get(supiOrGpsi)
	if !ok || uectx.State != smsfctx.StateActive {
		log.Warn("UplinkSMS: no active SMS context",
			"result", "REJECT", "cause", "CONTEXT_NOT_FOUND")
		s.problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND",
			"no active SMS context for "+supiOrGpsi)
		return
	}

	// The request is either the spec-literal multipart/related (JSON root part
	// + binary part, accepted whatever the SMSF profile) or the legacy JSON body.
	// Ref: TS 29.540 §5.2.4, TS 29.500 §5.4
	var req uplinkSMSRequest
	r.Body = http.MaxBytesReader(w, r.Body, features.MaxRequestBodyBytes)
	if sbi.IsRelated(r.Header.Get("Content-Type")) {
		id, payload, err := parseUplinkMultipart(r.Header.Get("Content-Type"), r.Body)
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) || errors.Is(err, sbi.ErrRelatedPartTooLarge) {
				payloadTooLarge(log, w, "UplinkSMS")
				return
			}
			cause, param := features.CauseInvalidMsgFormat, ""
			var me *errUplinkMultipart
			if errors.As(err, &me) {
				cause, param = me.cause, me.param
			}
			log.Warn("UplinkSMS: malformed multipart body",
				"result", "REJECT", "cause", cause, "error", err,
				"spec_ref", "TS 29.500 §5.2.7.2")
			s.problemParams(w, http.StatusBadRequest, cause, err.Error(), param)
			return
		}
		req = uplinkSMSRequest{SmsRecordId: id, SmsPayload: payload}
	} else if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			payloadTooLarge(log, w, "UplinkSMS")
			return
		}
		log.Warn("UplinkSMS: malformed body",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING", "error", err)
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "invalid JSON body")
		return
	}

	log.Info("UplinkSMS: MO SMS received",
		"sms_record_id", req.SmsRecordId,
		"supi", uectx.SUPI,
		"result", "OK",
		"spec_ref", "TS 29.540 §5.2.4",
	)

	// Return 200 immediately — the MO is accepted.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})

	// Loopback / echo DTE: reflect the MO payload back as an MT SMS to the same UE.
	// Use a detached background context so cancellation of the HTTP request context
	// (which happens when the response is sent) does not abort the MT delivery goroutine.
	// Ref: docs/procedures/sms-over-nas.md § "Loopback DTE"
	echoCtx := context.Background()
	go s.echoMTSMS(echoCtx, log, uectx, req.SmsPayload)
}

// echoMTSMS sends the MO payload back to the UE as an MT SMS via the AMF callback.
// Runs in a goroutine so handleUplinkSMS returns 200 promptly.
func (s *Server) echoMTSMS(
	ctx context.Context,
	log *slog.Logger,
	uectx *smsfctx.UESMSContext,
	smsPayload string,
) {
	callbackURI := uectx.AmfCallbackURI
	if callbackURI == "" {
		log.Warn("echoMTSMS: no AMF callback URI in context — cannot deliver MT SMS",
			"supi", uectx.SUPI,
			"result", "FAILURE",
		)
		return
	}

	if s.amfClient == nil {
		log.Warn("echoMTSMS: AMF client not configured — skipping MT delivery",
			"supi", uectx.SUPI,
			"callback_uri", callbackURI,
			"result", "FAILURE",
		)
		return
	}

	rawPayload := decodeBase64Payload(smsPayload)
	if err := s.amfClient.SendN1N2Message(ctx, callbackURI, uectx.SUPI, rawPayload); err != nil {
		log.Warn("echoMTSMS: Namf_Communication_N1N2MessageTransfer failed",
			"supi", uectx.SUPI,
			"callback_uri", callbackURI,
			"error", err,
			"result", "FAILURE",
			"interface", "Namf",
			"direction", "OUT",
			"spec_ref", "TS 29.518 §5.2.2.3",
		)
		return
	}

	log.Info("echoMTSMS: MT SMS delivered via AMF",
		"supi", uectx.SUPI,
		"callback_uri", callbackURI,
		"result", "OK",
		"interface", "Namf",
		"direction", "OUT",
		"spec_ref", "TS 29.518 §5.2.2.3",
	)
}

// ---- MT SMS internal trigger -----------------------------------------------

// handleMTSMSTrigger implements the internal MT SMS origination endpoint.
// POST /nsmsf-sms-internal/v1/ue-contexts/{supi}/mt-sms
// This is NOT a 3GPP endpoint — it is an operator convenience endpoint that
// lets the orchestrator / tests originate an SMSF-initiated MT SMS without
// requiring a real SMS-GMSC. Mirrors the SMF's internal mgmt endpoints.
func (s *Server) handleMTSMSTrigger(w http.ResponseWriter, r *http.Request) {
	supi := r.PathValue("supi")
	ctx := logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-Id"))
	log := logging.NewProcedureLogger(ctx, s.logger, "SmsOverNas").With(
		"nf", "SMSF",
		"procedure", "MTSmsTrigger",
		"interface", "Nsmsf",
		"direction", "IN",
		"spec_ref", "TS 23.502 §4.13.4",
		"supi", supi,
	)

	uectx, ok := s.store.Get(supi)
	if !ok || uectx.State != smsfctx.StateActive {
		log.Warn("MTSmsTrigger: no active context",
			"result", "REJECT", "cause", "CONTEXT_NOT_FOUND")
		s.problem(w, http.StatusNotFound, "CONTEXT_NOT_FOUND",
			"no active SMS context for "+supi)
		return
	}

	var req struct {
		SmsPayload string `json:"smsPayload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SmsPayload == "" {
		log.Warn("MTSmsTrigger: missing smsPayload",
			"result", "REJECT", "cause", "MANDATORY_IE_MISSING")
		s.problem(w, http.StatusBadRequest, "MANDATORY_IE_MISSING", "smsPayload is required")
		return
	}

	callbackURI := uectx.AmfCallbackURI
	if callbackURI == "" {
		log.Warn("MTSmsTrigger: no AMF callback URI in context",
			"supi", supi, "result", "FAILURE")
		s.problem(w, http.StatusServiceUnavailable, "AMF_CALLBACK_MISSING",
			"no AMF callback URI for this context")
		return
	}

	rawPayload := decodeBase64Payload(req.SmsPayload)

	if s.amfClient == nil {
		log.Warn("MTSmsTrigger: AMF client not configured",
			"supi", supi, "result", "FAILURE")
		// fail-open: still return 202 so tests can verify the call was accepted
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "queued", "warning": "AMF client not configured",
		})
		return
	}

	if err := s.amfClient.SendN1N2Message(ctx, callbackURI, supi, rawPayload); err != nil {
		log.Warn("MTSmsTrigger: N1N2MessageTransfer failed",
			"supi", supi, "error", err, "result", "FAILURE",
			"interface", "Namf", "direction", "OUT",
			"spec_ref", "TS 29.518 §5.2.2.3",
		)
		s.problem(w, http.StatusBadGateway, "AMF_DELIVERY_FAILED", err.Error())
		return
	}

	log.Info("MTSmsTrigger: MT SMS delivered via AMF",
		"supi", supi,
		"result", "OK",
		"interface", "Namf",
		"direction", "OUT",
		"spec_ref", "TS 29.518 §5.2.2.3",
	)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "delivered"})
}

// ---- Health ----------------------------------------------------------------

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"UP"}`))
}

// ---- helpers ---------------------------------------------------------------

// problem writes a 3GPP-style application/problem+json response.
// Ref: TS 29.500 §5.2.4 (ProblemDetails)
func (s *Server) problem(w http.ResponseWriter, status int, cause, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": status,
		"cause":  cause,
		"detail": detail,
	})
}

// problemParams is problem with an optional invalidParams entry (param is a
// JSON pointer; empty omits the list). Ref: TS 29.571 §5.2.4.1
func (s *Server) problemParams(w http.ResponseWriter, status int, cause, detail, param string) {
	body := map[string]any{"status": status, "cause": cause, "detail": detail}
	if param != "" {
		body["invalidParams"] = []map[string]string{{"param": param}}
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// decodeBase64Payload decodes a base64-encoded SMS payload string.
// If decoding fails, the raw UTF-8 bytes of the string are returned.
func decodeBase64Payload(s string) []byte {
	if s == "" {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return []byte(s)
	}
	return b
}

// HTTPAMFClient is the production AMF client implementation.
// It calls Namf_Communication_N1N2MessageTransfer over mTLS HTTP/2.
// Ref: TS 29.518 §5.2.2.3
type HTTPAMFClient struct {
	httpClient *http.Client
}

// NewHTTPAMFClient creates a new AMF client using the given HTTP/2 mTLS client.
func NewHTTPAMFClient(httpClient *http.Client) *HTTPAMFClient {
	return &HTTPAMFClient{httpClient: httpClient}
}

// SendN1N2Message delivers an MT SMS to the AMF via Namf_Communication_N1N2MessageTransfer.
// callbackURI is the full AMF endpoint URL for this UE context.
// Ref: TS 29.518 §5.2.2.3
func (c *HTTPAMFClient) SendN1N2Message(ctx context.Context, callbackURI, supi string, smsPayload []byte) error {
	body, _ := json.Marshal(map[string]any{
		"n1MessageContainer": map[string]any{
			"n1MessageClass": "SMS",
			// n1MessageContent carries the SMS payload as a base64 blob.
			// The AMF wraps this into a DL NAS Transport with PCT=0x02.
			// Ref: TS 29.518 §6.1.6.2.3 (N1MessageContainer), TS 24.501 §8.2.11
			"n1MessageContent": map[string]any{
				"contentId": "smsPayload",
			},
		},
		// Carry the raw SMS payload (base64) alongside for simplified AMF decoding.
		"smsPayload":           base64.StdEncoding.EncodeToString(smsPayload),
		"payloadContainerType": 2, // PCT=0x02 = SMS, TS 24.501 §9.11.3.40
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, callbackURI, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("smsf: amf client: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("smsf: amf client: N1N2MessageTransfer: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK &&
		resp.StatusCode != http.StatusAccepted &&
		resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("smsf: amf client: N1N2MessageTransfer status %d", resp.StatusCode)
	}
	return nil
}

// HTTPUDMClient is the production UDM client implementation for UECM registration.
type HTTPUDMClient struct {
	address    string
	httpClient *http.Client
}

// NewHTTPUDMClient creates a new UDM UECM client.
func NewHTTPUDMClient(address string, httpClient *http.Client) *HTTPUDMClient {
	return &HTTPUDMClient{address: address, httpClient: httpClient}
}

// RegisterSMSF registers the SMSF at UDM for the given SUPI.
// Ref: TS 29.503 §5.3.2.2 (Nudm_UECM_SMSFRegistration)
func (c *HTTPUDMClient) RegisterSMSF(ctx context.Context, supi, smsfInstanceID string) error {
	body, _ := json.Marshal(map[string]string{
		"smsfInstanceId": smsfInstanceID,
	})
	url := fmt.Sprintf("https://%s/nudm-uecm/v1/%s/registrations/smsf-3gpp-access",
		c.address, supi)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("smsf: udm client: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("smsf: udm client: UECM registration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK &&
		resp.StatusCode != http.StatusCreated &&
		resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("smsf: udm client: UECM registration: status %d", resp.StatusCode)
	}
	return nil
}
