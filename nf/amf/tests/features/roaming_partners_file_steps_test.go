//go:build functional

// In-process step definitions for roaming_partners_file.feature (SEPP-005: the AMF
// learns its roaming partners from the partners file; TS 23.502 §4.2.2.2.2,
// TS 29.500 §6.1.4.3, TS 24.501 §5.5.1.2.5; design in
// docs/procedures/N32InteropReadiness.md §3.4, §4.1, E12, E13).
//
// The registration scenarios reuse the roaming_registration world (rrWorld): the
// AMF is the real NAS + registration handlers with a roaming.Router that is built
// here by roaming.ResolveConfig / roaming.NewFromFile semantics from a temp
// partners file written per scenario. The SEPP, local AUSF and local UDM are
// httptest mocks recording every request.
//
// Limitation: the start-up scenarios (E12 and the missing file) cannot launch
// cmd/amf (package main, needs PostgreSQL/NRF). rpStartup mirrors the roaming
// block of cmd/amf/main.go (ResolveConfig, then roaming.New, ERROR log with
// cause "config_invalid" and exit status 1 on error); it calls the same
// production functions, so the file validation is the real one.
package features_test

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/cucumber/godog"

	"github.com/francurieses/claudia-5gc/nf/amf/internal/roaming"
)

// rpState is the per-scenario state of roaming_partners_file.feature.
type rpState struct {
	dir      string // temp dir holding the partners file
	path     string // partners file path, "" = none configured
	envSet   bool   // ROAMING_PARTNERS_FILE was set by this scenario
	envPrev  string
	envHad   bool
	started  bool
	exitCode int
	startCfg roaming.Config
}

// cleanup restores the environment and removes the temp dir (called from rrWorld.closeAll).
func (s *rpState) cleanup() {
	if s.envSet {
		if s.envHad {
			_ = os.Setenv(roaming.PartnersFileEnv, s.envPrev)
		} else {
			_ = os.Unsetenv(roaming.PartnersFileEnv)
		}
		s.envSet = false
	}
	if s.dir != "" {
		_ = os.RemoveAll(s.dir)
		s.dir = ""
	}
}

// setEnv points ROAMING_PARTNERS_FILE at the scenario file; restored by cleanup.
func (s *rpState) setEnv() error {
	if s.path == "" {
		return errors.New("no partners file prepared (missing Given step)")
	}
	if !s.envSet {
		s.envPrev, s.envHad = os.LookupEnv(roaming.PartnersFileEnv)
		s.envSet = true
	}
	return os.Setenv(roaming.PartnersFileEnv, s.path)
}

// write stores body as the scenario's partners file.
func (s *rpState) write(body string) error {
	if s.dir == "" {
		d, err := os.MkdirTemp("", "amf-partners-*")
		if err != nil {
			return fmt.Errorf("temp dir: %w", err)
		}
		s.dir = d
	}
	s.path = filepath.Join(s.dir, "partners.yaml")
	return os.WriteFile(s.path, []byte(body), 0o600)
}

// newRouter builds the roaming.Router of the world: inline config plus, when a
// partners file was prepared, the file resolved through ROAMING_PARTNERS_FILE
// (roaming.ResolveConfig), exactly as cmd/amf/main.go does.
func (w *rrWorld) newRouter(lg *slog.Logger) (*roaming.Router, error) {
	cfg := roaming.Config{Enabled: true, SEPPAddress: w.sepp.addr, HomePLMNs: w.homes}
	if w.rp.path != "" {
		if err := w.rp.setEnv(); err != nil {
			return nil, err
		}
		var err error
		if cfg, err = roaming.ResolveConfig(cfg, lg); err != nil {
			return nil, fmt.Errorf("roaming.ResolveConfig: %w", err)
		}
	}
	return roaming.New(cfg, w.mcc, w.mnc)
}

// rpMNC3 zero-pads an MNC to 3 digits (TS 23.003 §28.3.2.1 FQDN label).
func rpMNC3(m string) string { return strings.Repeat("0", 3-len(m)) + m }

func rpPartnerYAML(plmn, ausf, udm string) (string, error) {
	mcc, mnc, err := rrSplitPLMN(plmn)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("partners:\n  - plmn: {mcc: %q, mnc: %q}\n    n32:\n      address: sepp.5gc.mnc%s.mcc%s.3gppnetwork.org:8443\n"+
		"    home_nfs:\n      ausf_api_root: %s\n      udm_api_root: %s\n", mcc, mnc, rpMNC3(mnc), mcc, ausf, udm), nil
}

// ---- Givens ----------------------------------------------------------------

func rpEmptyHomePLMNs() error {
	rrW.homes = nil
	rrW.rp.path = ""
	return nil
}

func rpFileWithHomeNFs(plmn, ausf, udm string) error {
	y, err := rpPartnerYAML(plmn, ausf, udm)
	if err != nil {
		return err
	}
	return rrW.rp.write(y)
}

func rpFileWithoutHomeNFs(plmn string) error {
	mcc, mnc, err := rrSplitPLMN(plmn)
	if err != nil {
		return err
	}
	return rrW.rp.write(fmt.Sprintf("partners:\n  - plmn: {mcc: %q, mnc: %q}\n    n32:\n      address: sepp.5gc.mnc%s.mcc%s.3gppnetwork.org:8443\n",
		mcc, mnc, rpMNC3(mnc), mcc))
}

// rpStartedWithFile: the file is wired in through ROAMING_PARTNERS_FILE; the
// router is built lazily by rrWorld.build() on the When step.
func rpStartedWithFile() error { return rrW.rp.setEnv() }

func rpInvalidYAML() error { return rrW.rp.write("partners: [\n") }

func rpNonNumericMCC() error {
	return rrW.rp.write("partners:\n  - plmn: {mcc: \"0a1\", mnc: \"02\"}\n")
}

func rpDuplicate(plmn string) error {
	mcc, mnc, err := rrSplitPLMN(plmn)
	if err != nil {
		return err
	}
	e := fmt.Sprintf("  - plmn: {mcc: %q, mnc: %q}\n", mcc, mnc)
	return rrW.rp.write("partners:\n" + e + e)
}

func rpMissingFile() error {
	if rrW.rp.dir == "" {
		d, err := os.MkdirTemp("", "amf-partners-*")
		if err != nil {
			return err
		}
		rrW.rp.dir = d
	}
	rrW.rp.path = filepath.Join(rrW.rp.dir, "does-not-exist.yaml")
	return nil
}

// ---- Whens: AMF start-up (mirror of cmd/amf/main.go roaming block) ----------

func rpStartup() error {
	w := rrW
	if err := w.rp.setEnv(); err != nil {
		return err
	}
	lg := slog.New(slog.NewJSONHandler(w.logs, nil))
	cfg, err := roaming.ResolveConfig(roaming.Config{Enabled: true, SEPPAddress: w.sepp.addr, HomePLMNs: w.homes}, lg)
	if err == nil {
		_, err = roaming.New(cfg, w.mcc, w.mnc)
	}
	if err != nil {
		lg.Error("AMF: invalid roaming config", "nf", "AMF", "cause", "config_invalid", "error", err)
		w.rp.exitCode = 1
		return nil
	}
	w.rp.started, w.rp.startCfg = true, cfg
	return nil
}

// ---- Thens ------------------------------------------------------------------

func rpLocalAUSFZero() error {
	if n := rrW.lausf.snapshot(); len(n) != 0 {
		return fmt.Errorf("local AUSF mock received %d request(s): %v", len(n), n)
	}
	return nil
}

func rpAllThreeZero() error {
	if err := rrVSEPPZero(); err != nil {
		return err
	}
	return rrLocalZero()
}

func rpSEPPAndAUSFZero() error {
	if err := rrVSEPPZero(); err != nil {
		return err
	}
	return rpLocalAUSFZero()
}

func rpExitStatus(want int) error {
	if rrW.rp.started || rrW.rp.exitCode != want {
		return fmt.Errorf("AMF start-up: started=%v exit status=%d, want exit status %d", rrW.rp.started, rrW.rp.exitCode, want)
	}
	return nil
}

func rpErrorLogCause(cause string) error {
	for _, r := range rrW.records() {
		if strings.EqualFold(fmt.Sprint(r["level"]), "ERROR") && r["cause"] == cause {
			return nil
		}
	}
	return fmt.Errorf("no ERROR log line with cause %q; logs: %s", cause, rrW.logs.String())
}

func rpStartsOK() error {
	if !rrW.rp.started || rrW.rp.exitCode != 0 {
		return fmt.Errorf("AMF did not start (exit status %d, logs: %s)", rrW.rp.exitCode, rrW.logs.String())
	}
	return nil
}

func rpZeroHomePLMNs() error {
	if n := len(rrW.rp.startCfg.HomePLMNs); n != 0 {
		return fmt.Errorf("AMF holds %d home PLMN(s), want 0: %v", n, rrW.rp.startCfg.HomePLMNs)
	}
	return nil
}

func initRoamingPartnersSteps(sc *godog.ScenarioContext) {
	sc.Step(`^the AMF configuration has an empty home_plmns list and no partners file$`, rpEmptyHomePLMNs)
	sc.Step(`^a roaming partners file with partner PLMN "([^"]*)" and home_nfs ausf_api_root "([^"]*)" and udm_api_root "([^"]*)"$`, rpFileWithHomeNFs)
	sc.Step(`^a roaming partners file with partner PLMN "([^"]*)" that has an n32 section but no home_nfs$`, rpFileWithoutHomeNFs)
	sc.Step(`^the AMF is started with ROAMING_PARTNERS_FILE pointing at that file$`, rpStartedWithFile)
	sc.Step(`^a partners file that is not valid YAML$`, rpInvalidYAML)
	sc.Step(`^a partners file with a partner whose plmn has a non-numeric mcc$`, rpNonNumericMCC)
	sc.Step(`^a partners file with two entries for PLMN "([^"]*)"$`, rpDuplicate)
	sc.Step(`^ROAMING_PARTNERS_FILE points to a file that does not exist$`, rpMissingFile)

	sc.Step(`^the AMF starts with ROAMING_PARTNERS_FILE pointing at that file$`, rpStartup)
	sc.Step(`^the AMF starts$`, rpStartup)

	sc.Step(`^the local AUSF mock received zero requests$`, rpLocalAUSFZero)
	sc.Step(`^the SEPP mock, the local AUSF mock and the local UDM mock received zero requests$`, rpAllThreeZero)
	sc.Step(`^the SEPP mock and the local AUSF mock received zero requests$`, rpSEPPAndAUSFZero)
	sc.Step(`^the AMF exits with status (\d+)$`, rpExitStatus)
	sc.Step(`^the AMF log has an ERROR line with cause "([^"]*)"$`, rpErrorLogCause)
	sc.Step(`^the AMF starts successfully$`, rpStartsOK)
	sc.Step(`^the AMF holds zero home PLMNs$`, rpZeroHomePLMNs)
}
