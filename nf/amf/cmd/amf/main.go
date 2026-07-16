// Package main is the entry point of the AMF (Access and Mobility Management Function).
// 3GPP TS 29.518 — AMF Services.
// 3GPP TS 38.413 — NG Application Protocol (NGAP).
// 3GPP TS 24.501 — 5GS Non-Access Stratum (NAS) protocol.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"gopkg.in/yaml.v3"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	nasmsg "github.com/francurieses/claudia-5gc/nf/amf/internal/nas"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	amfsbi "github.com/francurieses/claudia-5gc/nf/amf/internal/sbi"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/store"
	"github.com/francurieses/claudia-5gc/shared/nrf"
	"github.com/francurieses/claudia-5gc/shared/oauth2"
	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	"github.com/francurieses/claudia-5gc/shared/observability/tracing"
	"github.com/francurieses/claudia-5gc/shared/sbi"

	operatorcfg "github.com/francurieses/claudia-5gc/shared/config"
)

const nfName = "AMF"

// NGAPSenderWithSMF wraps NGAP server and SMF client to implement the Sender interface
// while providing access to SMF for PDU session handling.
type NGAPSenderWithSMF struct {
	ngap *ngap.Server
	smf  *HTTPSMFClient
	// nrfDisc is optional: when set, SMF is discovered per slice via NRF.
	nrfDisc *HTTPNRFClient
}

// SendDownlinkNASTransport delegates to NGAP server.
func (s *NGAPSenderWithSMF) SendDownlinkNASTransport(ue *amfctx.UEContext, nasPDU []byte) error {
	return s.ngap.SendDownlinkNASTransport(ue, nasPDU)
}

// SendInitialContextSetupRequest delegates to NGAP server.
func (s *NGAPSenderWithSMF) SendInitialContextSetupRequest(ue *amfctx.UEContext, nasPDU []byte,
	kgnb [32]byte, cipherAlg, integAlg byte,
	encAlgsBitmap, intAlgsBitmap uint16,
	pduSessions []ngap.PDUSessionSetupItemCxtReq) error {
	return s.ngap.SendInitialContextSetupRequest(ue, nasPDU, kgnb, cipherAlg, integAlg, encAlgsBitmap, intAlgsBitmap, pduSessions)
}

// ActivateSMContext asks the SMF for the PDUSessionResourceSetupRequestTransfer
// of an existing session (upCnxState=ACTIVATING) during Service Request UP
// re-activation. Ref: TS 29.502 §5.2.2.3.2.2
func (s *NGAPSenderWithSMF) ActivateSMContext(ctx context.Context, smContextRef string) ([]byte, error) {
	return s.smf.ActivateSMContext(ctx, smContextRef)
}

// SendPDUSessionResourceSetupRequest delegates to NGAP server.
func (s *NGAPSenderWithSMF) SendPDUSessionResourceSetupRequest(ue *amfctx.UEContext,
	pduSessionID uint8, nasPDU []byte, n2SmInfo []byte) error {
	return s.ngap.SendPDUSessionResourceSetupRequest(ue, pduSessionID, nasPDU, n2SmInfo)
}

// SendPDUSessionResourceReleaseCommand delegates to NGAP server.
func (s *NGAPSenderWithSMF) SendPDUSessionResourceReleaseCommand(ue *amfctx.UEContext, pduSessionID uint8, nasPDU []byte) error {
	return s.ngap.SendPDUSessionResourceReleaseCommand(ue, pduSessionID, nasPDU)
}

// CallSMF calls the SMF CreateSMContext API with the resolved S-NSSAI.
// If an NRF discovery client is configured, the SMF address is resolved per slice;
// otherwise falls back to the statically configured SMF address.
func (s *NGAPSenderWithSMF) CallSMF(ctx context.Context, supi, dnn string,
	pduSessionID uint8, n1SmMsg []byte, snssai amfctx.SNSSAISubscribed) (string, []byte, []byte, error) {
	smf := s.smf
	if s.nrfDisc != nil {
		addr, err := s.nrfDisc.DiscoverSMFAddress(ctx, snssai)
		if err == nil && addr != "" {
			smf = &HTTPSMFClient{address: addr, client: s.smf.client}
		}
	}
	return smf.CreateSMContext(ctx, supi, dnn, pduSessionID, n1SmMsg, snssai)
}

// DeleteSMContext calls the SMF DeleteSMContext API.
func (s *NGAPSenderWithSMF) DeleteSMContext(ctx context.Context, smContextRef string) error {
	return s.smf.DeleteSMContext(ctx, smContextRef)
}

// NotifyANRelease notifies SMF that the UE went CM-IDLE.
func (s *NGAPSenderWithSMF) NotifyANRelease(ctx context.Context, smContextRef string) error {
	return s.smf.NotifyANRelease(ctx, smContextRef)
}

// SendPDUSessionResourceModifyRequest delegates to NGAP server.
func (s *NGAPSenderWithSMF) SendPDUSessionResourceModifyRequest(ue *amfctx.UEContext,
	pduSessionID uint8, nasPDU []byte, n2SmInfo []byte) error {
	return s.ngap.SendPDUSessionResourceModifyRequest(ue, pduSessionID, nasPDU, n2SmInfo)
}

// ModifySMContext calls the SMF ModifySMContext API.
func (s *NGAPSenderWithSMF) ModifySMContext(ctx context.Context, smContextRef string, n1SmMsg []byte, pduSessionID uint8) ([]byte, []byte, error) {
	return s.smf.ModifySMContext(ctx, smContextRef, n1SmMsg, pduSessionID)
}

// ModifyQoSSMContext forwards NW-initiated QoS policy update to the SMF.
func (s *NGAPSenderWithSMF) ModifyQoSSMContext(ctx context.Context, smContextRef string, pduSessionID uint8, fiveQI, ambrDLMbps, ambrULMbps int) ([]byte, []byte, error) {
	return s.smf.ModifyQoSSMContext(ctx, smContextRef, pduSessionID, fiveQI, ambrDLMbps, ambrULMbps)
}

// SendUEContextReleaseCommandForUE triggers AMF-initiated UE context release.
func (s *NGAPSenderWithSMF) SendUEContextReleaseCommandForUE(ue *amfctx.UEContext, causePresent int, causeValue int64) error {
	return s.ngap.SendUEContextReleaseCommandForUE(ue, causePresent, causeValue)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				a.Value = slog.StringValue(time.Now().UTC().Format(time.RFC3339Nano))
			}
			return a
		},
	}))
	logger = logger.With("nf", nfName)
	slog.SetDefault(logger)

	cfg, err := loadConfig(cfgPath())
	if err != nil {
		logger.Error("loading config", "error", err)
		os.Exit(1)
	}
	logger = logger.With("nf_instance_id", cfg.NFInstanceID)
	slog.SetDefault(logger)

	// ---- Tracing (OTel → Jaeger) ------------------------------------------
	otlpEndpoint := getEnvDefault("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4318")
	tracingCtx := context.Background()
	tp, err := tracing.Init(tracingCtx, nfName, otlpEndpoint)
	if err != nil {
		logger.Warn("tracing init failed, running without traces", "error", err)
	} else {
		defer func() {
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := tp.Shutdown(shutCtx); err != nil {
				logger.Warn("tracer shutdown error", "error", err)
			}
		}()
		logger.Info("OTel tracer initialised", "endpoint", otlpEndpoint)
	}

	// ---- Metrics server (Prometheus) --------------------------------------
	metricsAddr := getEnvDefault("METRICS_ADDRESS", cfg.Metrics.Address)
	if metricsAddr == "" {
		metricsAddr = "0.0.0.0:9101"
	}
	metricsSrv := metrics.MetricsServer(metricsAddr)
	go func() {
		logger.Info("metrics server listening", "addr", metricsAddr)
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server", "error", err)
		}
	}()

	// ---- Build NF clients -------------------------------------------------
	// Use mTLS client when cert/key are configured; fall back to TLS-only.
	var httpClient *http.Client
	if cfg.SBI.TLSCert != "" && cfg.SBI.TLSKey != "" && cfg.SBI.TLSCa != "" {
		httpClient, err = sbi.NewMTLSClient(cfg.SBI.TLSCa, cfg.SBI.TLSCert, cfg.SBI.TLSKey)
	} else {
		httpClient, err = sbi.NewHTTP2Client(cfg.SBI.TLSCa)
	}
	if err != nil {
		logger.Error("building http2 client", "error", err)
		os.Exit(1)
	}
	httpClient.Transport = otelhttp.NewTransport(httpClient.Transport)

	// Wrap client with OAuth2 Bearer transport when NRF and secret are configured.
	sbiClient := httpClient
	var nrfBase string
	if cfg.Peers.NRFAddress != "" {
		nrfBase = "https://" + cfg.Peers.NRFAddress
		tokenURL := nrfBase + "/oauth2/v1/token"
		tokenCache := oauth2.NewTokenCache(httpClient, tokenURL, cfg.NFInstanceID, "namf-comm")
		sbiClient = oauth2.NewBearerClient(httpClient, tokenCache)
		logger.Info("OAuth2 Bearer transport enabled",
			"token_url", tokenURL,
			"spec_ref", "TS 33.501 §13.4.1",
		)
	}

	ausfClient := &HTTPAUSFClient{
		address: cfg.Peers.AUSFAddress,
		client:  sbiClient,
	}
	udmClient := &HTTPUDMClient{
		address: cfg.Peers.UDMAddress,
		client:  sbiClient,
	}
	smfClient := &HTTPSMFClient{
		address: cfg.Peers.SMFAddress,
		client:  sbiClient,
	}

	// ---- Persistent store (PostgreSQL) + cache (Redis) --------------------
	var ueStore store.Store
	var ueCache store.Cache
	if dsn := getEnvDefault("DATABASE_URL", cfg.DatabaseURL); dsn != "" {
		pg, err := store.NewPostgres(context.Background(), dsn)
		if err != nil {
			logger.Warn("AMF PostgreSQL unavailable — running in-memory only",
				"error", err, "dsn_hint", "set DATABASE_URL")
		} else {
			ueStore = pg
			defer pg.Close()
			logger.Info("AMF PostgreSQL store connected")
		}
	}
	if redisAddr := getEnvDefault("REDIS_URL", cfg.RedisURL); redisAddr != "" {
		rc, err := store.NewRedisCache(redisAddr)
		if err != nil {
			logger.Warn("AMF Redis unavailable — using local TMSI counter",
				"error", err, "addr", redisAddr)
		} else {
			ueCache = rc
			defer rc.Close()
			logger.Info("AMF Redis cache connected", "addr", redisAddr)
		}
	}

	// ---- AMF context manager ----------------------------------------------
	amfID := amfctx.AMFIdentity{
		MCC:         cfg.PLMN.MCC,
		MNC:         cfg.PLMN.MNC,
		AMFRegionID: cfg.AMFRegionID,
		AMFSetID:    cfg.AMFSetID,
		AMFID:       cfg.AMFID,
	}
	mgr := amfctx.NewManager(amfID, ueStore, ueCache, logger)
	// LoadFromStore purges the previous run's UE contexts; give it a way to release
	// their SM contexts at the SMF first, or every restart orphans an SMF session,
	// a UPF PFCP session and a UE IP per PDU session. Bounded per call: the SMF may
	// still be booting and startup must not block on it.
	// Ref: TS 23.007 §16, TS 29.502 §5.2.2.3.3.
	mgr.SetSMContextReleaser(func(ctx context.Context, smContextRef string) error {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return smfClient.DeleteSMContext(ctx, smContextRef)
	})
	if err := mgr.LoadFromStore(context.Background()); err != nil {
		logger.Warn("AMF: LoadFromStore failed — starting with empty context", "error", err)
	}

	// ---- NRF discovery client (optional) -----------------------------------
	var nrfDiscClient *HTTPNRFClient
	if nrfBase != "" {
		nrfDiscClient = NewHTTPNRFClient(nrfBase, sbiClient)
	}

	// ---- Registration handler (procedures) --------------------------------
	regHandler := procedures.NewRegistrationHandler(
		mgr, ausfClient, udmClient, nrfDiscClient,
		cfg.NFInstanceID, cfg.PLMN.MCC, cfg.PLMN.MNC, logger,
	)
	if cfg.Peers.NSSFAddress != "" {
		regHandler.WithNSSF(&HTTPNSSFClient{
			address: cfg.Peers.NSSFAddress,
			client:  sbiClient,
		})
		logger.Info("NSSF slice selection enabled",
			"nssf_addr", cfg.Peers.NSSFAddress,
			"spec_ref", "TS 23.502 §4.2.9",
		)
	}
	// PCF client (N15 — Npcf_UEPolicyControl) — optional, non-fatal if absent.
	// Delivers URSP rules to UEs at registration and via on-demand push.
	// URSP delivery can be turned off with URSP_ENABLED=false (or config
	// features.ursp_enabled: false) to run the core without URSP — the AMF then
	// makes no N15 call and sends no UE policy container.
	// Ref: TS 29.525 §4.2.2.2
	urspEnabled := urspEnabledFromEnv(cfg.Features.URSPEnabled)
	var pcfClient *HTTPPCFClient
	if cfg.Peers.PCFAddress != "" && urspEnabled {
		pcfClient = &HTTPPCFClient{
			address: cfg.Peers.PCFAddress,
			client:  sbiClient,
		}
		regHandler.WithPCF(pcfClient)
		logger.Info("PCF N15 UE policy delivery enabled",
			"pcf_addr", cfg.Peers.PCFAddress,
			"ursp_enabled", true,
			"spec_ref", "TS 29.525 §4.2.2.2",
		)
	} else {
		logger.Warn("URSP delivery disabled — AMF will not request or deliver UE policies",
			"ursp_enabled", false,
			"reason", urspDisabledReason(cfg.Peers.PCFAddress, urspEnabled),
		)
	}

	// AM Policy Association (Npcf_AMPolicyControl, TS 29.507 §4.2.2).
	// Created at UE registration (step 14c); non-fatal if PCF unavailable.
	if cfg.Peers.PCFAddress != "" {
		amPolicyClient := &HTTPAMPolicyClient{
			address: cfg.Peers.PCFAddress,
			client:  sbiClient,
		}
		regHandler.WithAMPolicy(amPolicyClient)
		logger.Info("PCF AM policy association enabled",
			"pcf_addr", cfg.Peers.PCFAddress,
			"spec_ref", "TS 29.507 §4.2.2",
		)
	}

	// NSSAA (Network Slice-Specific Authentication and Authorization, TS 23.502 §4.2.9).
	// Slices flagged subjectToNssaa in the subscription are EAP-authenticated with the
	// AAA-S, relayed through the AUSF, before being added to the Allowed NSSAI. Enabled
	// whenever the AUSF peer is configured (the AUSF fronts the simulated AAA-S).
	if cfg.Peers.AUSFAddress != "" {
		regHandler.WithNSSAA(&HTTPNSSAAClient{
			address: cfg.Peers.AUSFAddress,
			client:  sbiClient,
		})
		logger.Info("NSSAA slice authentication enabled",
			"ausf_addr", cfg.Peers.AUSFAddress,
			"spec_ref", "TS 23.502 §4.2.9",
		)
	}

	// Operator default RFSP index included in every NGAP InitialContextSetupRequest.
	// PCF AM policy overrides this per-subscriber when available.
	// Configure via operator.default_rfsp in nf/amf/config/dev.yaml (default 1).
	// Ref: TS 38.413 §9.3.1.27, TS 23.501 §5.3.4.2
	defaultRFSP := cfg.Operator.DefaultRFSP
	if defaultRFSP == 0 {
		defaultRFSP = 1 // always send RFSP=1 unless explicitly disabled (set to -1 in config)
	}
	if defaultRFSP > 0 {
		regHandler.WithDefaultRFSP(defaultRFSP)
		logger.Info("operator default RFSP configured",
			"rfsp", defaultRFSP,
			"spec_ref", "TS 38.413 §9.3.1.27",
		)
	}

	// T3512 Periodic Registration Timer sent to UE in Registration Accept.
	// Configure via timers.t3512_secs in nf/amf/config/dev.yaml.
	// Ref: TS 24.501 §8.2.7.1 (IEI 0x5E), §10.2
	regHandler.WithT3512(cfg.Timers.T3512Secs)
	// Registration area (TAI list, IEI 0x54) sent in every Registration Accept.
	// Ref: TS 24.501 §9.11.3.9
	regHandler.WithServedTACs(cfg.ServedTACs)
	logger.Info("AMF served TACs configured",
		"served_tacs", cfg.ServedTACs,
		"spec_ref", "TS 24.501 §9.11.3.9",
	)
	if cfg.Security.NullCiphering {
		regHandler.WithNullSecurity(true)
		logger.Warn("NAS null ciphering active: NEA0 (no encryption) + best-available NIA — plain-text NAS — DEBUG ONLY",
			"spec_ref", "TS 33.501 §6.7.2",
		)
	}
	logger.Info("AMF timers configured",
		"t3512_secs", cfg.Timers.T3512Secs,
		"mobile_reachable_secs", cfg.Timers.T3512Secs+cfg.Timers.MobileReachableGuardSecs,
		"implicit_detach_secs", cfg.Timers.ImplicitDetachSecs,
		"pending_removal_watchdog_secs", cfg.Timers.PendingRemovalWatchdogSecs,
		"spec_ref", "TS 23.501 §5.3.2, TS 24.501 §10.2",
	)

	// ---- NGAP server -------------------------------------------------------
	var amfSNSSAIs []amfctx.SNSSAISubscribed
	for _, s := range cfg.SNSSAIs {
		amfSNSSAIs = append(amfSNSSAIs, amfctx.SNSSAISubscribed{SST: s.SST, SD: s.SD})
	}
	ngapSrv := ngap.NewServer(cfg.NGAP.Address, mgr, nil, ngap.AMFConfig{
		Name:     "5GC-AMF",
		MCC:      cfg.PLMN.MCC,
		MNC:      cfg.PLMN.MNC,
		RegionID: cfg.AMFRegionID,
		SetID:    cfg.AMFSetID,
		AMFID:    cfg.AMFID,
		SNSSAIs:  amfSNSSAIs,
	}, logger)
	// Configure UE lifecycle timer durations.
	// Ref: TS 23.501 §5.3.2 (Mobile Reachable, Implicit Detach), TS 38.413 §8.3.5
	ngapSrv.WithTimerConfig(ngap.TimerConfig{
		MobileReachable: time.Duration(cfg.Timers.T3512Secs+cfg.Timers.MobileReachableGuardSecs) * time.Second,
		ImplicitDetach:  time.Duration(cfg.Timers.ImplicitDetachSecs) * time.Second,
		PendingRemoval:  time.Duration(cfg.Timers.PendingRemovalWatchdogSecs) * time.Second,
	})

	// ---- NAS handler -------------------------------------------------------
	// Create wrapper that implements Sender interface with SMF capability
	sender := &NGAPSenderWithSMF{
		ngap:    ngapSrv,
		smf:     smfClient,
		nrfDisc: nrfDiscClient,
	}
	nasHandler := nasmsg.NewHandler(sender, regHandler, logger)

	// SMS over NAS: forward UL NAS Transport SMS containers (PCT=0x02) to the SMSF
	// via Nsmsf_SMService_UplinkSMS. Enabled when the SMSF peer is configured.
	// Ref: TS 23.502 §4.13.3, TS 29.540 §5.2.4
	if cfg.Peers.SMSFAddress != "" {
		nasHandler.WithSMSFClient(&HTTPSMSFClient{
			address: cfg.Peers.SMSFAddress,
			client:  sbiClient,
		})
		logger.Info("SMS over NAS enabled — UL NAS Transport SMS routed to SMSF",
			"smsf_addr", cfg.Peers.SMSFAddress,
			"spec_ref", "TS 29.540 §5.2.4",
		)
	} else {
		logger.Warn("SMSF peer not configured — UL NAS Transport SMS will be dropped (fail-open)",
			"spec_ref", "TS 29.540 §5.2.4",
		)
	}

	// Wire NAS handler back into NGAP server (circular dep resolved via interface)
	ngapSrv.SetNASHandler(nasHandler)

	// sbiSrv is forward-declared here so the onUEReachable closure below can
	// reference it without a circular init dependency. It is assigned later in
	// the cfg.SBI.Address block. By the time any Service Request arrives (which
	// fires onUEReachable), ngapSrv.Start() has been called, guaranteeing that
	// sbiSrv is already assigned. Ref: TS 23.273 §7.2 steps E2–E7.
	var sbiSrv *amfsbi.Server

	// A UE entering CM-CONNECTED (registration complete, service request,
	// registration update) is reachable: cancel the Mobile Reachable / Implicit
	// Detach watchdogs. The NGAP layer re-arms them on AN Release (CM-IDLE).
	// Also wake any pending paging-then-locate waiter in the SBI server.
	// Ref: TS 23.501 §5.3.2, TS 24.501 §5.3.7, TS 23.273 §7.2 steps E2–E7.
	nasHandler.SetUEReachableHandler(func(ue *amfctx.UEContext) {
		ngapSrv.StopUETimers(ue)
		// Unblock any Namf_Location paging-then-locate waiter for this UE.
		if s := sbiSrv; s != nil {
			s.NotifyUEReachable(ue.AMFUENGAPId)
		}
		// If the UE was paged for mobile-terminated data, the Service Request that
		// brought it back to CM-CONNECTED re-activates the user plane: clear the flag.
		// Ref: TS 23.502 §4.2.3.3
		ue.Lock()
		paged := ue.PendingN1N2
		ue.PendingN1N2 = false
		supi := ue.SUPI
		ue.Unlock()
		if paged {
			logger.Info("paged UE returned via Service Request — user plane re-activated",
				"procedure", "NetworkTriggeredServiceRequest",
				"supi", supi,
				"result", "OK",
				"spec_ref", "TS 23.502 §4.2.3.3",
			)
		}
	})

	// When gNB confirms PDU session resources, forward the N2SM response transfer
	// to SMF so it can update PFCP with the DL TEID from the gNB.
	// Ref: TS 23.502 §4.3.2.2.1 step 9
	ngapSrv.SetPDUSessionResponseHandler(func(ctx context.Context, smContextRef string, n2SmTransfer []byte) {
		if err := smfClient.UpdateSMContext(ctx, smContextRef, n2SmTransfer); err != nil {
			logger.Error("SMF UpdateSMContext failed",
				"smContextRef", smContextRef, "error", err)
		}
	})

	// When the gNB reports a PDU session in FailedToSetupListSURes, release the
	// SM context at the SMF so the UE IP and PFCP session are freed.
	// Ref: TS 38.413 §8.4.1, TS 23.502 §4.3.2.2.1 step 16
	ngapSrv.SetPDUSessionSetupFailureHandler(func(ctx context.Context, smContextRef string) {
		if err := smfClient.DeleteSMContext(ctx, smContextRef); err != nil {
			logger.Error("SMF DeleteSMContext failed for gNB-rejected PDU session",
				"smContextRef", smContextRef, "error", err)
		}
	})

	// When UE Context Release Complete is received (UE → CM-IDLE), notify the SMF
	// for each PDU session so it can deactivate the UPF DL forwarding path.
	// Ref: TS 23.502 §4.2.6, TS 29.502 §5.2.2.3.2
	ngapSrv.SetANReleaseHandler(func(ctx context.Context, ue *amfctx.UEContext) {
		ue.Lock()
		sessions := make(map[uint8]*amfctx.PDUSession, len(ue.PDUSessions))
		for k, v := range ue.PDUSessions {
			sessions[k] = v
		}
		ue.Unlock()

		for _, sess := range sessions {
			if sess.SMFInstanceID == "" {
				continue
			}
			if err := smfClient.NotifyANRelease(ctx, sess.SMFInstanceID); err != nil {
				logger.Error("SMF NotifyANRelease failed",
					"smContextRef", sess.SMFInstanceID,
					"supi", ue.SUPI,
					"error", err,
				)
			}
		}
	})

	// When the SCTP association with a gNB drops abruptly (e.g., container stop),
	// release all PDU sessions at SMF and remove UE contexts for every UE that was
	// CM-CONNECTED on that gNB at the time of the disconnect.
	// Ref: TS 23.502 §4.2.6 (implicit detach on RAN failure)
	ngapSrv.SetGNBDisconnectHandler(func(ctx context.Context, ue *amfctx.UEContext) {
		ue.Lock()
		sessions := make(map[uint8]*amfctx.PDUSession, len(ue.PDUSessions))
		for k, v := range ue.PDUSessions {
			sessions[k] = v
		}
		supi := ue.SUPI
		ue.Unlock()

		for _, sess := range sessions {
			if sess.SMFInstanceID == "" {
				continue
			}
			if err := smfClient.DeleteSMContext(ctx, sess.SMFInstanceID); err != nil {
				logger.Warn("SMF DeleteSMContext failed on gNB disconnect",
					"smContextRef", sess.SMFInstanceID,
					"supi", supi,
					"error", err,
				)
			} else {
				logger.Info("PDU session released on gNB disconnect",
					"procedure", "GNBDisconnect",
					"smContextRef", sess.SMFInstanceID,
					"supi", supi,
					"spec_ref", "TS 23.502 §4.2.6",
				)
			}
		}

		if supi != "" {
			if err := udmClient.DeregisterUECM(ctx, supi); err != nil {
				logger.Warn("UDM UECM deregistration failed on gNB disconnect",
					"supi", supi, "error", err)
			}
		}

		mgr.Remove(ctx, ue)
		logger.Info("UE context removed on gNB disconnect",
			"procedure", "GNBDisconnect",
			"supi", supi,
			"spec_ref", "TS 23.502 §4.2.6",
		)
	})

	// When the Implicit Detach Timer fires (UE has been unreachable since Mobile
	// Reachable Timer expired), release all PDU sessions, deregister from UDM,
	// and remove the UE context. Same cleanup path as gNB disconnect.
	// Ref: TS 23.501 §5.3.2
	ngapSrv.SetImplicitDetachHandler(func(ctx context.Context, ue *amfctx.UEContext) {
		ue.Lock()
		sessions := make(map[uint8]*amfctx.PDUSession, len(ue.PDUSessions))
		for k, v := range ue.PDUSessions {
			sessions[k] = v
		}
		supi := ue.SUPI
		ue.Unlock()

		for _, sess := range sessions {
			if sess.SMFInstanceID == "" {
				continue
			}
			if err := smfClient.DeleteSMContext(ctx, sess.SMFInstanceID); err != nil {
				logger.Warn("SMF DeleteSMContext failed on implicit detach",
					"smContextRef", sess.SMFInstanceID,
					"supi", supi,
					"error", err,
				)
			} else {
				logger.Info("PDU session released on implicit detach",
					"procedure", "ImplicitDetach",
					"smContextRef", sess.SMFInstanceID,
					"supi", supi,
					"spec_ref", "TS 23.501 §5.3.2",
				)
			}
		}

		if supi != "" {
			if err := udmClient.DeregisterUECM(ctx, supi); err != nil {
				logger.Warn("UDM UECM deregistration failed on implicit detach",
					"supi", supi, "error", err)
			}
		}

		mgr.Remove(ctx, ue)
		logger.Info("UE context removed — implicit detach complete",
			"procedure", "ImplicitDetach",
			"supi", supi,
			"result", "OK",
			"spec_ref", "TS 23.501 §5.3.2",
		)
	})

	// Xn Handover: when target gNB sends PathSwitchRequest, update PFCP in SMF
	// with the new DL GTP-U endpoint from the PathSwitchRequestTransfer.
	// Ref: TS 23.502 §4.9.1.2 step 6
	ngapSrv.SetPathSwitchHandler(func(ctx context.Context, smContextRef string, pathSwitchTransfer []byte) {
		if err := smfClient.UpdatePathSwitch(ctx, smContextRef, pathSwitchTransfer); err != nil {
			logger.Warn("SMF UpdatePathSwitch failed on Xn handover",
				"smContextRef", smContextRef, "error", err,
				"spec_ref", "TS 23.502 §4.9.1.2",
			)
		} else {
			logger.Info("SMF path switch update complete",
				"procedure", "XnHandover",
				"smContextRef", smContextRef,
				"spec_ref", "TS 23.502 §4.9.1.2",
			)
		}
	})

	// ---- Start servers -----------------------------------------------------
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ---- NRF registration + heartbeat ------------------------------------
	if nrfBase != "" {
		nrfClient := nrf.New(nrfBase, httpClient, logger)
		profile := &nrf.NFProfile{
			NFInstanceID: cfg.NFInstanceID,
			NFType:       "AMF",
			NFStatus:     "REGISTERED",
			NFServices: []nrf.NFService{{
				ServiceInstanceID: cfg.NFInstanceID + "-namf-comm",
				ServiceName:       "namf-comm",
				Scheme:            "https",
				NFServiceStatus:   "REGISTERED",
				Versions:          []nrf.NFServiceVersion{{APIVersionInURI: "v1", APIFullVersion: "1.0.0"}},
			}},
		}
		if err := nrfClient.RegisterAndStartHeartbeat(ctx, profile, 45*time.Second); err != nil {
			logger.Warn("NRF registration failed (continuing without NRF)",
				"nrf_addr", nrfBase, "error", err,
				"spec_ref", "TS 29.510 §5.2.2.2.2",
			)
		}
	}

	// ---- Inbound SBI server (namf-comm — UEContextTransfer) ----------------
	// First AMF inbound SBI server. Serves Namf_Communication_UEContextTransfer
	// so a new AMF can retrieve the UE MM/security context + PDU sessions during
	// Registration with AMF change. Ref: TS 29.518 §5.3.2, TS 23.502 §4.2.2.2.3.
	if cfg.SBI.Address != "" {
		var err error
		sbiSrv, err = amfsbi.New(amfsbi.Config{
			Address:  cfg.SBI.Address,
			CertFile: cfg.SBI.TLSCert,
			KeyFile:  cfg.SBI.TLSKey,
			CAFile:   cfg.SBI.TLSCa,
		}, mgr, logger)
		if err != nil {
			logger.Error("building AMF inbound SBI server", "error", err)
			os.Exit(1)
		}
		// Wire NGAP paging trigger for N1N2MessageTransfer (CN paging of CM-IDLE UEs).
		// Ref: TS 23.502 §4.2.3.3, TS 38.413 §9.2.8.
		sbiSrv.SetPager(ngapSrv)
		// Wire NGAP location trigger for Namf_Location_ProvideLocationInfo.
		// The NGAP server sends LocationReportingControl and delivers the LocationReport
		// via a channel keyed by AMF-UE-NGAP-ID.
		// Ref: TS 29.518 §5.2.2.6; TS 38.413 §8.17.1; TS 23.273 §7.2.
		sbiSrv.SetLocator(ngapSrv)
		// Wire NGAP NRPPa relay for Namf_Location dl-nrppa-info.
		// The NGAP server sends DownlinkUEAssociatedNRPPaTransport and delivers the
		// matching UplinkUEAssociatedNRPPaTransport via a channel keyed by AMF-UE-NGAP-ID.
		// Ref: TS 38.413 §8.17.3; TS 23.273 §7.2 step C.
		sbiSrv.SetNRPPaRelay(ngapSrv)
		// Wire the NAS LPP relay for Namf_Location dl-lpp-info (LMF-005).
		// nasHandler sends the DL NAS Transport (payload container type 0x03) and
		// delivers the matching UL NAS Transport LPP container via a channel keyed
		// by AMF-UE-NGAP-ID. Ref: TS 24.501 §8.7.4; TS 23.273 §7.2.
		sbiSrv.SetLPPRelay(nasHandler)
		go func() {
			if err := sbiSrv.Start(ctx); err != nil {
				logger.Error("AMF inbound SBI server", "error", err)
			}
		}()
	}

	// ---- Management HTTP server (NW-initiated operations) -------------------
	// Exposes admin endpoints for operator-triggered actions.
	// DELETE /amf/v1/ue-contexts/{supi}                        → NW-initiated Deregistration (§4.2.2.3.3)
	// DELETE /amf/v1/ue-contexts/{supi}/pdu-sessions/{psi}     → NW-initiated PDU Session Release (§4.3.4.3)
	// POST   /amf/v1/ue-contexts/{supi}/push-policies          → Trigger UCU with fresh URSP from PCF (TS 23.502 §4.2.4)
	mgmtAddr := getEnvDefault("MANAGEMENT_ADDRESS", "0.0.0.0:9002")
	mgmtMux := http.NewServeMux()

	mgmtMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// GET /amf/v1/ue-contexts — list all active UE context snapshots (read-only).
	// Consumed by the MCP server's ue_list tool.
	mgmtMux.HandleFunc("GET /amf/v1/ue-contexts", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mgr.ListContexts())
	})

	// GET /amf/v1/ue-contexts/{supi} — single UE context snapshot (read-only).
	// Consumed by the MCP server's ue_context_get / gmm_state_get tools.
	mgmtMux.HandleFunc("GET /amf/v1/ue-contexts/{supi}", func(w http.ResponseWriter, r *http.Request) {
		supi := r.PathValue("supi")
		ue, ok := mgr.GetBySUPI(supi)
		if !ok {
			http.Error(w, "UE not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ue.Snapshot())
	})

	// POST /amf/v1/ue-contexts/{supi}/push-policies — trigger UCU for a registered UE.
	// Fetches fresh URSP rules from PCF and delivers them via ConfigurationUpdateCommand.
	// Returns 204 on success, 409 if the UE is CM-IDLE (delivery deferred).
	// Ref: TS 23.502 §4.2.4, TS 29.525 §4.2.2.2
	mgmtMux.HandleFunc("POST /amf/v1/ue-contexts/{supi}/push-policies", func(w http.ResponseWriter, r *http.Request) {
		supi := r.PathValue("supi")
		if supi == "" {
			http.Error(w, "supi required", http.StatusBadRequest)
			return
		}
		if pcfClient == nil {
			if !urspEnabled {
				http.Error(w, "URSP delivery is disabled (URSP_ENABLED=false)", http.StatusServiceUnavailable)
				return
			}
			http.Error(w, "PCF not configured", http.StatusServiceUnavailable)
			return
		}
		ue, found := mgr.GetBySUPI(supi)
		if !found {
			http.Error(w, "UE not found", http.StatusNotFound)
			return
		}
		plmn := cfg.PLMN.MCC + cfg.PLMN.MNC
		container, polAssoID, err := procedures.FetchUEPolicyContainer(r.Context(), ue, pcfClient, plmn)
		if errors.Is(err, procedures.ErrNotConnected) {
			http.Error(w, "UE is CM-IDLE — policy delivery deferred", http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if polAssoID != "" {
			ue.Lock()
			ue.PolicyAssociationID = polAssoID
			ue.Unlock()
		}
		if len(container) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err := nasHandler.SendUEPolicyContainer(r.Context(), ue, container); errors.Is(err, procedures.ErrNotConnected) {
			http.Error(w, "UE is CM-IDLE — policy delivery deferred", http.StatusConflict)
			return
		} else if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		logger.Info("UE policy delivery (push-policies) triggered",
			"supi", supi, "pol_asso_id", polAssoID,
			"procedure", "UEPolicyDelivery",
			"spec_ref", "TS 23.502 §4.2.4.3",
		)
		w.WriteHeader(http.StatusNoContent)
	})

	// POST /amf/v1/ue-contexts/{supi}/nssaa/{reauth|revoke} — AAA-initiated NSSAA.
	// Simulates the Nnssaaf re-auth / revocation notification from the AAA-S. Body:
	// {"sst": int, "sd": "hexstr"}. Ref: TS 23.502 §4.2.9.3 (re-auth) / §4.2.9.4 (revoke).
	nssaaTrigger := func(w http.ResponseWriter, r *http.Request, revoke bool) {
		supi := r.PathValue("supi")
		var req struct {
			SST uint8  `json:"sst"`
			SD  string `json:"sd"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		ue, found := mgr.GetBySUPI(supi)
		if !found {
			http.Error(w, "UE not found", http.StatusNotFound)
			return
		}
		var ok bool
		if revoke {
			ok = nasHandler.RevokeNSSAASlice(r.Context(), ue, req.SST, req.SD)
		} else {
			ok = nasHandler.ReauthNSSAASlice(r.Context(), ue, req.SST, req.SD)
		}
		if !ok {
			http.Error(w, "slice not in Allowed NSSAI for this UE", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
	mgmtMux.HandleFunc("POST /amf/v1/ue-contexts/{supi}/nssaa/revoke", func(w http.ResponseWriter, r *http.Request) {
		nssaaTrigger(w, r, true)
	})
	mgmtMux.HandleFunc("POST /amf/v1/ue-contexts/{supi}/nssaa/reauth", func(w http.ResponseWriter, r *http.Request) {
		nssaaTrigger(w, r, false)
	})

	// PATCH /amf/v1/ue-contexts/{supi}/pdu-sessions/{psi}/qos — NW-initiated QoS modification.
	// Body: {"5qi": int, "ambr_dl_mbps": int, "ambr_ul_mbps": int}
	// Flow: PCF override already set by caller → trigger SMF policy-update → forward N1SM+N2SM to gNB.
	// Ref: TS 23.502 §4.3.3.2
	mgmtMux.HandleFunc("PATCH /amf/v1/ue-contexts/{supi}/pdu-sessions/{psi}/qos", func(w http.ResponseWriter, r *http.Request) {
		supi := r.PathValue("supi")
		psiStr := r.PathValue("psi")
		if supi == "" || psiStr == "" {
			http.Error(w, "supi and psi required", http.StatusBadRequest)
			return
		}
		psi64, err := strconv.ParseUint(psiStr, 10, 8)
		if err != nil {
			http.Error(w, "invalid pdu session id", http.StatusBadRequest)
			return
		}
		psi := uint8(psi64)

		var req struct {
			FiveQI     int `json:"5qi"`
			AMBRDLMbps int `json:"ambr_dl_mbps"`
			AMBRULMbps int `json:"ambr_ul_mbps"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if req.FiveQI <= 0 || req.FiveQI > 86 {
			http.Error(w, "5qi must be 1-86", http.StatusBadRequest)
			return
		}
		if req.AMBRDLMbps <= 0 {
			req.AMBRDLMbps = 100
		}
		if req.AMBRULMbps <= 0 {
			req.AMBRULMbps = 100
		}

		ue, found := mgr.GetBySUPI(supi)
		if !found {
			http.Error(w, "UE not found", http.StatusNotFound)
			return
		}

		if err := nasHandler.InitiateNetworkQoSModification(r.Context(), ue, psi, req.FiveQI, req.AMBRDLMbps, req.AMBRULMbps); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		logger.Info("NW-initiated QoS Modification triggered",
			"supi", supi, "pdu_session_id", psi,
			"5qi", req.FiveQI, "ambr_dl_mbps", req.AMBRDLMbps, "ambr_ul_mbps", req.AMBRULMbps,
			"procedure", "NetworkQoSModification",
			"spec_ref", "TS 23.502 §4.3.3.2",
		)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accepted":       true,
			"supi":           supi,
			"pdu_session_id": psi,
			"5qi":            req.FiveQI,
			"ambr_dl_mbps":   req.AMBRDLMbps,
			"ambr_ul_mbps":   req.AMBRULMbps,
		})
	})

	// NW-initiated PDU Session Release: DELETE /amf/v1/ue-contexts/{supi}/pdu-sessions/{psi}
	// Also handles GET /amf/v1/ue-contexts/ (Go's ServeMux redirects the no-slash
	// form to this subtree root when a method-less subtree handler exists).
	mgmtMux.HandleFunc("/amf/v1/ue-contexts/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path[len("/amf/v1/ue-contexts/"):]
		if path == "" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(mgr.ListContexts())
			return
		}
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Check for /pdu-sessions/{psi} suffix
		if idx := len(path) - len("/pdu-sessions/"); idx > 0 {
			// path might be "{supi}/pdu-sessions/{psi}"
			const pdusuffix = "/pdu-sessions/"
			if sepIdx := len(path); sepIdx > 0 {
				for i := 0; i < len(path)-len(pdusuffix); i++ {
					if path[i:i+len(pdusuffix)] == pdusuffix {
						supi := path[:i]
						psiStr := path[i+len(pdusuffix):]
						if supi == "" || psiStr == "" {
							break
						}
						psi, err := strconv.ParseUint(psiStr, 10, 8)
						if err != nil {
							http.Error(w, "invalid pdu session id", http.StatusBadRequest)
							return
						}
						ue, found := mgr.GetBySUPI(supi)
						if !found {
							http.Error(w, "UE not found", http.StatusNotFound)
							return
						}
						if err := nasHandler.InitiateNetworkPDUSessionRelease(r.Context(), ue, uint8(psi)); err != nil {
							http.Error(w, err.Error(), http.StatusInternalServerError)
							return
						}
						logger.Info("NW-initiated PDU Session Release triggered",
							"supi", supi, "pdu_session_id", psi,
							"procedure", "NetworkPDUSessionRelease",
							"spec_ref", "TS 23.502 §4.3.4.3",
						)
						w.WriteHeader(http.StatusAccepted)
						return
					}
				}
			}
		}

		// Default: NW-initiated Deregistration
		supi := path
		if supi == "" {
			http.Error(w, "supi required", http.StatusBadRequest)
			return
		}
		ue, found := mgr.GetBySUPI(supi)
		if !found {
			http.Error(w, "UE not found", http.StatusNotFound)
			return
		}
		// No 5GMM cause + "re-registration required": the UE must come back and
		// re-fetch its (possibly updated) subscription. A cause like 0x06 (illegal
		// ME) would invalidate the USIM on the UE (5U3) — TS 24.501 §5.5.2.3.4.
		if err := nasHandler.SendNetworkDeregistration(r.Context(), ue, 0, 1, true); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		logger.Info("NW-initiated Deregistration triggered",
			"supi", supi,
			"procedure", "NetworkDeregistration",
			"spec_ref", "TS 23.502 §4.2.2.3.3",
		)
		w.WriteHeader(http.StatusAccepted)
	})
	// GET /amf/v1/ue-contexts/{supi}/nas-keys — return NAS security keys for Wireshark decryption.
	// DEV-ONLY: never expose this endpoint in production.
	mgmtMux.HandleFunc("GET /amf/v1/ue-contexts/{supi}/nas-keys", func(w http.ResponseWriter, r *http.Request) {
		supi := r.PathValue("supi")
		if supi == "" {
			http.Error(w, "supi required", http.StatusBadRequest)
			return
		}
		ue, found := mgr.GetBySUPI(supi)
		if !found {
			http.Error(w, "UE not found", http.StatusNotFound)
			return
		}
		ue.Lock()
		sc := ue.SecurityCtx
		ue.Unlock()
		if !sc.Active {
			http.Error(w, "no active security context for this UE", http.StatusConflict)
			return
		}
		algNames := map[byte]string{0: "NEA0 (null)", 1: "NEA1 (SNOW3G)", 2: "NEA2 (AES-CTR)", 3: "NEA3 (ZUC)"}
		resp := map[string]any{
			"supi":            supi,
			"cipher_alg_id":   sc.CipheringAlgID,
			"cipher_alg_name": algNames[sc.CipheringAlgID],
			"k_nasenc_hex":    hex.EncodeToString(sc.KNASenc),
			"k_nasint_hex":    hex.EncodeToString(sc.KNASint),
			"nas_dl_count":    sc.DownlinkCount,
			"nas_ul_count":    sc.UplinkCount,
			"wireshark_hint":  "Edit → Preferences → Protocols → NAS-5GS → enter k_nasenc_hex as the NAS Encryption Key",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mgmtSrv := &http.Server{Addr: mgmtAddr, Handler: mgmtMux}
	go func() {
		logger.Info("management server listening", "addr", mgmtAddr)
		if err := mgmtSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("management server", "error", err)
		}
	}()

	// Background goroutine: publish UE gauges every 10 s
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				metrics.UERegistered.WithLabelValues(nfName).Set(float64(mgr.RegisteredCount()))
				metrics.UEConnected.WithLabelValues(nfName).Set(float64(mgr.ConnectedCount()))
				// Per-slice UE counts: reset and re-publish on each tick.
				sliceCounts := mgr.CountBySlice()
				metrics.UERegisteredBySlice.Reset()
				for k, cnt := range sliceCounts {
					metrics.UERegisteredBySlice.WithLabelValues(
						nfName, fmt.Sprintf("%d", k.SST), k.SD,
					).Set(float64(cnt))
				}
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		if err := ngapSrv.Start(ctx); err != nil {
			errCh <- fmt.Errorf("ngap: %w", err)
		}
	}()

	logger.Info("AMF ready",
		"ngap_addr", cfg.NGAP.Address,
		"plmn", fmt.Sprintf("%s/%s", cfg.PLMN.MCC, cfg.PLMN.MNC),
		"spec_ref", "TS 23.501 §6.2.1",
	)

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		logger.Error("server error", "error", err)
		os.Exit(1)
	}

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = metricsSrv.Shutdown(shutCtx)
	_ = mgmtSrv.Shutdown(shutCtx)

	logger.Info("AMF stopped cleanly")
}

// ---- Config ---------------------------------------------------------------

type Config struct {
	NFInstanceID string `yaml:"nf_instance_id"`
	PLMN         struct {
		MCC string `yaml:"mcc"`
		MNC string `yaml:"mnc"`
	} `yaml:"plmn"`
	AMFRegionID uint8  `yaml:"amf_region_id"`
	AMFSetID    uint16 `yaml:"amf_set_id"`
	AMFID       uint8  `yaml:"amf_id"`
	// ServedTACs is the registration area (TAI list) advertised to every UE in
	// Registration Accept (IEI 0x54). The UE's current TAC is always added even
	// if missing here. Defaults to [1] (matches config/ueransim/gnb.yaml tac: 1).
	// Ref: TS 24.501 §9.11.3.9, TS 23.501 §5.3.2.3
	ServedTACs []uint32 `yaml:"served_tacs"`
	// Persistence — overridden by DATABASE_URL / REDIS_URL env vars.
	DatabaseURL string `yaml:"database_url"`
	RedisURL    string `yaml:"redis_url"`
	NGAP        struct {
		Address string `yaml:"address"` // host:port (38412)
	} `yaml:"ngap"`
	SBI struct {
		Address string `yaml:"address"` // SBI HTTP/2 port
		TLSCert string `yaml:"cert_file"`
		TLSKey  string `yaml:"key_file"`
		TLSCa   string `yaml:"ca_file"`
	} `yaml:"sbi"`
	Peers struct {
		NRFAddress  string `yaml:"nrf"`
		AUSFAddress string `yaml:"ausf"`
		UDMAddress  string `yaml:"udm"`
		SMFAddress  string `yaml:"smf"`
		NSSFAddress string `yaml:"nssf"`
		PCFAddress  string `yaml:"pcf"`
		SMSFAddress string `yaml:"smsf"`
	} `yaml:"peers"`
	// SNSSAIs is the list of slices served by this AMF (advertised in NG Setup Response).
	SNSSAIs []struct {
		SST uint8  `yaml:"sst"`
		SD  string `yaml:"sd"`
	} `yaml:"snssais"`
	Metrics struct {
		Address string `yaml:"address"`
	} `yaml:"metrics"`
	// Timers configures UE lifecycle timers. All values in seconds.
	// Ref: TS 23.501 §5.3.2 (Mobile Reachable / Implicit Detach),
	//      TS 24.501 §10.2 (T3512), TS 38.413 §8.3.5 (PendingRemoval watchdog).
	// To change: edit nf/amf/config/dev.yaml section "timers:" and restart the AMF.
	Timers struct {
		T3512Secs                  int `yaml:"t3512_secs"`
		MobileReachableGuardSecs   int `yaml:"mobile_reachable_guard_secs"`
		ImplicitDetachSecs         int `yaml:"implicit_detach_secs"`
		PendingRemovalWatchdogSecs int `yaml:"pending_removal_watchdog_secs"`
	} `yaml:"timers"`
	// Security overrides — for dev/debug only.
	// null_ciphering: true forces NEA0+NIA0 so NAS PDUs travel in plain text.
	// NEVER set in production. Ref: TS 33.501 §6.7.2
	Security struct {
		NullCiphering bool `yaml:"null_ciphering"`
	} `yaml:"security"`
	// Features toggles optional behaviours. Overridable by environment variables.
	Features struct {
		// URSPEnabled controls whether the AMF requests URSP from the PCF (N15)
		// and delivers a UE policy container to the UE. nil = default (enabled).
		// Overridden by the URSP_ENABLED environment variable.
		URSPEnabled *bool `yaml:"ursp_enabled"`
	} `yaml:"features"`
	// Operator holds operator-wide policy defaults applied to every UE.
	Operator struct {
		// DefaultRFSP is the Radio Frequency Selection Priority index (1-256)
		// included in every NGAP InitialContextSetupRequest (IE id=31) when PCF
		// does not provide a per-subscriber value. 0 = use built-in default (1).
		// Set to -1 to omit the IE entirely (not recommended).
		// Ref: TS 38.413 §9.3.1.27, TS 23.501 §5.3.4.2
		DefaultRFSP int `yaml:"default_rfsp"`
	} `yaml:"operator"`
}

// urspEnabledFromEnv resolves the effective URSP toggle. Precedence:
// URSP_ENABLED env var → config features.ursp_enabled → default (enabled).
func urspEnabledFromEnv(configVal *bool) bool {
	if v := os.Getenv("URSP_ENABLED"); v != "" {
		switch v {
		case "0", "false", "no", "off", "FALSE", "False":
			return false
		default:
			return true
		}
	}
	if configVal != nil {
		return *configVal
	}
	return true
}

// urspDisabledReason explains why URSP delivery is off, for the startup log.
func urspDisabledReason(pcfAddr string, urspEnabled bool) string {
	if pcfAddr == "" {
		return "no PCF peer configured"
	}
	if !urspEnabled {
		return "URSP_ENABLED=false"
	}
	return "unknown"
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	// Seed PLMN + slices from operator config before per-NF YAML overwrites.
	var c Config
	if op, err := operatorcfg.LoadOperator(""); err != nil {
		return nil, fmt.Errorf("operator config: %w", err)
	} else if op != nil {
		c.PLMN.MCC = op.PLMN.MCC
		c.PLMN.MNC = op.PLMN.MNC
		for _, s := range op.Slices() {
			c.SNSSAIs = append(c.SNSSAIs, struct {
				SST uint8  `yaml:"sst"`
				SD  string `yaml:"sd"`
			}{SST: uint8(s.SST), SD: s.SD})
		}
	}
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if c.NFInstanceID == "" {
		c.NFInstanceID = "00000000-0000-4001-8000-000000000001"
	}
	if c.NGAP.Address == "" {
		c.NGAP.Address = "0.0.0.0:38412"
	}
	// Apply timer defaults (dev-friendly values; override in config YAML for prod).
	if c.Timers.T3512Secs == 0 {
		c.Timers.T3512Secs = 60
	}
	if c.Timers.MobileReachableGuardSecs == 0 {
		c.Timers.MobileReachableGuardSecs = 120
	}
	if c.Timers.ImplicitDetachSecs == 0 {
		c.Timers.ImplicitDetachSecs = 60
	}
	if c.Timers.PendingRemovalWatchdogSecs == 0 {
		c.Timers.PendingRemovalWatchdogSecs = 30
	}
	if len(c.ServedTACs) == 0 {
		c.ServedTACs = []uint32{1}
	}
	return &c, nil
}

func cfgPath() string {
	if p := os.Getenv("CONFIG_PATH"); p != "" {
		return p
	}
	return "/etc/5gc/config.yaml"
}

func getEnvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func healthcheck() int {
	addr := os.Getenv("HEALTHCHECK_ADDR")
	if addr == "" {
		addr = "http://127.0.0.1:8001/healthz"
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(addr)
	if err != nil || resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
