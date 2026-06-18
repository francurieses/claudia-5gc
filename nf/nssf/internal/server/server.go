// Package server implements the HTTP/2 SBI server for the NSSF.
//
// Endpoints (3GPP TS 29.531 v17):
//
//	GET /nnssf-nsselection/v2/network-slice-information   NSSelection_Get
//	GET /healthz                                          Liveness probe
//	GET /metrics                                          Prometheus metrics
//
// Ref: TS 29.531 §5.2.2.2
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/francurieses/claudia-5gc/nf/nssf/internal/config"
	"github.com/francurieses/claudia-5gc/nf/nssf/internal/slice"
)

// Server is the NSSF SBI server.
type Server struct {
	cfg    *config.Config
	logger *slog.Logger
	policy *slice.Store
	httpSrv *http.Server
}

// New constructs a new NSSF server.
func New(cfg *config.Config, logger *slog.Logger) *Server {
	allowed := make([]slice.SliceID, 0, len(cfg.AllowedSlices))
	for _, s := range cfg.AllowedSlices {
		allowed = append(allowed, slice.SliceID{SST: s.SST, SD: s.SD})
	}
	if len(allowed) == 0 {
		allowed = []slice.SliceID{{SST: 1, SD: "000001"}}
	}

	s := &Server{
		cfg:    cfg,
		logger: logger,
		policy: slice.New(allowed),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /nnssf-nsselection/v2/network-slice-information", s.handleNSSelection)
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.Handle("GET /metrics", promhttp.Handler())

	handler := http.Handler(mux)

	s.httpSrv = &http.Server{
		Addr:    cfg.SBI.Address,
		Handler: h2c.NewHandler(handler, &http2.Server{}),
	}
	return s
}

// Start starts the NSSF server with TLS if configured.
func (s *Server) Start(ctx context.Context) error {
	if s.cfg.SBI.TLS.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.SBI.TLS.CertFile, s.cfg.SBI.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("nssf: load TLS cert: %w", err)
		}
		caPEM, err := os.ReadFile(s.cfg.SBI.TLS.CAFile)
		if err != nil {
			return fmt.Errorf("nssf: load CA: %w", err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caPEM)
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    pool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{"h2"},
		}
		// Assign TLSConfig before ConfigureServer so http2.ConfigureServer sees
		// the real config and does not create a temporary one that gets overwritten.
		s.httpSrv.TLSConfig = tlsCfg
		if err := http2.ConfigureServer(s.httpSrv, &http2.Server{}); err != nil {
			return fmt.Errorf("nssf: configure http2: %w", err)
		}
		s.logger.Info("NSSF SBI listening (TLS)", "addr", s.cfg.SBI.Address)
		if err := s.httpSrv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("nssf: listen: %w", err)
		}
		return nil
	}
	s.logger.Info("NSSF SBI listening (plain/h2c)", "addr", s.cfg.SBI.Address)
	if err := s.httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("nssf: listen: %w", err)
	}
	return nil
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

// handleNSSelection implements GET /nnssf-nsselection/v2/network-slice-information.
// Ref: TS 29.531 §5.2.2.2.3.1
func (s *Server) handleNSSelection(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	nfType := q.Get("nf-type")
	nfID := q.Get("nf-id")
	if nfType == "" || nfID == "" {
		problem(w, http.StatusBadRequest, "MANDATORY_QUERY_PARAM_MISSING",
			"nf-type and nf-id are mandatory")
		return
	}

	// Parse requestedNssai from query parameter (JSON-encoded array of S-NSSAIs)
	// Ref: TS 29.531 §6.1.6.2.3 — SliceInfoForRegistration.requestedNssai
	var requested []slice.SliceID
	if raw := q.Get("slice-info-request-for-registration.requestedNssai"); raw != "" {
		var list []struct {
			SST int    `json:"sst"`
			SD  string `json:"sd"`
		}
		if err := json.Unmarshal([]byte(raw), &list); err == nil {
			for _, s := range list {
				requested = append(requested, slice.SliceID{SST: s.SST, SD: s.SD})
			}
		}
	} else if rawSST := q.Get("requested-nssai.sst"); rawSST != "" {
		// Alternate form: individual query params
		sst, _ := strconv.Atoi(rawSST)
		requested = []slice.SliceID{{SST: sst, SD: q.Get("requested-nssai.sd")}}
	}

	allowed := s.policy.SelectForRegistration(requested)

	s.logger.Info("NSSelection",
		"procedure", "NSSelection",
		"nf_type", nfType,
		"nf_id", nfID,
		"requested_count", len(requested),
		"allowed_count", len(allowed),
		"interface", "N22",
		"direction", "OUT",
		"spec_ref", "TS 29.531 §5.2.2.2",
	)

	// Build response: AuthorizedNetworkSliceInfo
	// Ref: TS 29.531 §6.1.6.2.3 (AuthorizedNetworkSliceInfo)
	type snssai struct {
		SST int    `json:"sst"`
		SD  string `json:"sd,omitempty"`
	}
	type allowedNSSAI struct {
		AllowedSnssaiList []snssai `json:"allowedSnssaiList"`
		AccessType        string   `json:"accessType"`
	}

	allowedList := make([]snssai, 0, len(allowed))
	for _, a := range allowed {
		allowedList = append(allowedList, snssai{SST: a.SST, SD: a.SD})
	}

	resp := map[string]any{
		"allowedNssaiList": []allowedNSSAI{
			{
				AllowedSnssaiList: allowedList,
				AccessType:        "3GPP_ACCESS",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"UP"}`))
}

func problem(w http.ResponseWriter, status int, cause, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": status,
		"cause":  cause,
		"detail": detail,
	})
}
