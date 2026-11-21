//go:build functional

// In-process step definitions for nas_security_algorithms.feature (SEC-006: NAS
// ciphering with 128-NEA1 / 128-NEA3; TS 33.501 §6.7.1.1, §6.7.2, Annex D;
// TS 24.501 §4.4.4, §4.4.6, §9.11.3.34).
//
// The AMF side is the real nasmsg.Handler + procedures.RegistrationHandler driven
// through HandleNASMessage with a fake AUSF / UDM / SMSF and a recording N2
// sender. The UE side is played by the steps: every uplink PDU is built and every
// downlink PDU is deciphered with shared/crypto/nas/nea NEA1/NEA2/NEA3 and
// shared/crypto/nas/nia directly, with keys derived independently through
// shared/crypto/kdf, so the AMF dispatch (cipherNAS) is never reused as oracle.
package features_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/cucumber/godog"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	nasmsg "github.com/francurieses/claudia-5gc/nf/amf/internal/nas"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nea"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nia"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

const (
	nsaSUPI  = "imsi-001010000000001"
	nsaMsgRR = 0x44 // REGISTRATION REJECT, TS 24.501 §8.2.9
	nsaMsgRA = 0x42 // REGISTRATION ACCEPT, TS 24.501 §8.2.7
	nsaMsgAR = 0x56 // AUTHENTICATION REQUEST, TS 24.501 §8.2.1
	nsaMsgSC = 0x5D // SECURITY MODE COMMAND, TS 24.501 §8.2.25
)

// nsaKAUSF is the fixed KAUSF the AUSF mock hands back with the RES* confirmation.
var nsaKAUSF = bytes.Repeat([]byte{0x6b}, 32)

// nsaSender records the NAS PDUs the AMF hands to the N2 layer (DL NAS TRANSPORT
// and the INITIAL CONTEXT SETUP REQUEST NAS-PDU) and implements nasmsg.Sender.
type nsaSender struct {
	mu  sync.Mutex
	dl  [][]byte
	rel int
}

func (s *nsaSender) add(p []byte) {
	s.mu.Lock()
	s.dl = append(s.dl, append([]byte(nil), p...))
	s.mu.Unlock()
}

func (s *nsaSender) SendDownlinkNASTransport(_ *amfctx.UEContext, p []byte) error {
	s.add(p)
	return nil
}

func (s *nsaSender) SendInitialContextSetupRequest(_ *amfctx.UEContext, p []byte, _ [32]byte,
	_, _ byte, _, _ uint16, _ []ngap.PDUSessionSetupItemCxtReq) error {
	s.add(p)
	return nil
}

func (s *nsaSender) SendPDUSessionResourceSetupRequest(*amfctx.UEContext, uint8, []byte, []byte) error {
	return nil
}
func (s *nsaSender) SendPDUSessionResourceReleaseCommand(*amfctx.UEContext, uint8, []byte) error {
	return nil
}
func (s *nsaSender) SendPDUSessionResourceModifyRequest(*amfctx.UEContext, uint8, []byte, []byte) error {
	return nil
}
func (s *nsaSender) SendUEContextReleaseCommandForUE(*amfctx.UEContext, int, int64) error {
	s.mu.Lock()
	s.rel++
	s.mu.Unlock()
	return nil
}

func (s *nsaSender) snapshot() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.dl...)
}

// nsaAUSF confirms any RES* and counts authentication initiations.
type nsaAUSF struct {
	mu    sync.Mutex
	inits int
}

func (a *nsaAUSF) InitiateAuth(context.Context, string, string) (*procedures.AUSFInitResponse, error) {
	a.mu.Lock()
	a.inits++
	a.mu.Unlock()
	return &procedures.AUSFInitResponse{AuthCtxID: "auth-1", SUPI: nsaSUPI}, nil
}
func (a *nsaAUSF) ResyncAuth(context.Context, string, string, [16]byte, []byte) (*procedures.AUSFInitResponse, error) {
	return &procedures.AUSFInitResponse{AuthCtxID: "auth-2"}, nil
}
func (a *nsaAUSF) ConfirmAuth(context.Context, string, string) (*procedures.AUSFConfirmResponse, error) {
	return &procedures.AUSFConfirmResponse{SUPI: nsaSUPI, KAUSF: nsaKAUSF}, nil
}
func (a *nsaAUSF) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.inits
}

// nsaUDM serves one subscribed S-NSSAI.
type nsaUDM struct{}

func (nsaUDM) RegisterAMF(context.Context, string, string, string) error { return nil }
func (nsaUDM) GetAMSubscriptionData(context.Context, string) (*procedures.UDMAMSubscription, error) {
	s := []amfctx.SNSSAISubscribed{{SST: 1}}
	return &procedures.UDMAMSubscription{AllowedNSSAI: s, DefaultNSSAI: s}, nil
}
func (nsaUDM) DeregisterUECM(context.Context, string) error { return nil }

// nsaSMSF records the UL NAS TRANSPORT SMS containers, which reach it only if the
// AMF deciphered the uplink message to the plain 5GMM message.
type nsaSMSF struct {
	mu       sync.Mutex
	payloads [][]byte
}

func (f *nsaSMSF) UplinkSMS(_ context.Context, _, _, b64 string) error {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.payloads = append(f.payloads, raw)
	f.mu.Unlock()
	return nil
}
func (f *nsaSMSF) got() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.payloads...)
}

type nsaSyncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *nsaSyncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *nsaSyncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// nsaWorld is the per-scenario state.
type nsaWorld struct {
	mgr    *amfctx.Manager
	reg    *procedures.RegistrationHandler
	h      *nasmsg.Handler
	sender *nsaSender
	ausf   *nsaAUSF
	smsf   *nsaSMSF
	logs   *nsaSyncBuf
	ue     *amfctx.UEContext

	ea, ia [4]bool // advertised 5G-EA0..3 / 5G-IA0..3

	// UE-side security context, derived independently of the AMF.
	alg     byte
	intAlg  byte // selected NIA (0 = not yet known, treated as NIA2)
	macAlg  byte // when non-zero, the UE MACs uplink with this NIA instead (negative tests)
	kamf    []byte
	knasenc []byte
	knasint []byte
	ulCount uint32

	smc        []byte // the SECURITY MODE COMMAND PDU as sent on N1
	smcMark    int    // DL index of the SMC
	accept     []byte // the REGISTRATION ACCEPT PDU (SHT 2)
	acceptDLAt int
	ausfBase   int
	dlBase     int

	lastErr error // error returned by the last AMF operation

	// configuration scenarios
	cfgOrder []byte
	cfgErr   error
}

var nsaW *nsaWorld

// ---- helpers --------------------------------------------------------------

func nsaUECipher(alg byte, key []byte, count uint32, dir byte, msg []byte) ([]byte, error) {
	switch alg {
	case 0:
		return append([]byte(nil), msg...), nil
	case 1:
		return nea.NEA1(key, count, 0x01, dir, msg)
	case 2:
		return nea.NEA2(key, count, 0x01, dir, msg)
	case 3:
		return nea.NEA3(key, count, 0x01, dir, msg)
	}
	return nil, fmt.Errorf("UE side: no such NEA%d", alg)
}

func nsaNEAByName(name string) (byte, error) {
	if len(name) == 4 && strings.HasPrefix(name, "NEA") && name[3] >= '0' && name[3] <= '3' {
		return name[3] - '0', nil
	}
	return 0, fmt.Errorf("unknown algorithm name %q", name)
}

func nsaCapOctets(ea, ia [4]bool) (byte, byte) {
	var e, i byte
	for k := 0; k < 4; k++ {
		if ea[k] {
			e |= 0x80 >> uint(k)
		}
		if ia[k] {
			i |= 0x80 >> uint(k)
		}
	}
	return e, i
}

// nia returns the integrity algorithm the UE side uses (NIA2 until an SMC fixed it).
func (w *nsaWorld) nia() byte {
	if w.intAlg == 0 {
		return 2
	}
	return w.intAlg
}

// nsaUEMAC computes the NAS-MAC on the UE side with the named NIA, straight from
// shared/crypto/nas/nia so the AMF dispatch (computeNASMAC) is never the oracle.
func nsaUEMAC(alg byte, key []byte, count uint32, dir byte, msg []byte) ([]byte, error) {
	switch alg {
	case 1:
		return nia.NIA1(key, count, 0x01, dir, msg)
	case 2:
		return nia.NIA2(key, count, 0x01, dir, msg)
	case 3:
		return nia.NIA3(key, count, 0x01, dir, msg)
	}
	return nil, fmt.Errorf("UE side: no such NIA%d", alg)
}

func nsaNIAByName(name string) (byte, error) {
	if len(name) == 4 && strings.HasPrefix(name, "NIA") && name[3] >= '1' && name[3] <= '3' {
		return name[3] - '0', nil
	}
	return 0, fmt.Errorf("unknown integrity algorithm name %q", name)
}

func (w *nsaWorld) deriveUEKeys(alg byte) {
	// TS 33.501 §A.2/§A.7; serving network name for PLMN 001/01.
	snn := "5G:mnc001.mcc001.3gppnetwork.org"
	kseaf := kdf.KSEAF(nsaKAUSF, snn)
	w.kamf = kdf.KAMF(kseaf, strings.TrimPrefix(nsaSUPI, "imsi-"), [2]byte{0, 0})
	w.alg = alg
	w.knasenc = kdf.KNASenc(w.kamf, alg)
	w.knasint = kdf.KNASint(w.kamf, w.nia())
}

func (w *nsaWorld) newHandler() {
	lg := slog.New(slog.NewJSONHandler(w.logs, nil))
	w.mgr = amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01", AMFRegionID: 2, AMFID: 1}, nil, nil, nil)
	w.reg = procedures.NewRegistrationHandler(w.mgr, w.ausf, nsaUDM{}, nil, "nf", "001", "01", lg)
	w.h = nasmsg.NewHandler(w.sender, w.reg, lg)
	w.h.WithSMSFClient(w.smsf)
}

func (w *nsaWorld) newUE(id int64) *amfctx.UEContext {
	ue := w.mgr.AllocateUEContext(id)
	ue.RANUENGAPId = id
	ue.GNBAddr = "10.0.0.1:38412"
	ue.CMState = amfctx.CMConnected
	return ue
}

// ueIE returns a PLMN-001/01 SUCI (null scheme) mobile identity LV-E.
func nsaSUCIIdentity() []byte {
	v := []byte{0x01, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}
	return append([]byte{0x00, byte(len(v))}, v...)
}

// registrationRequest builds a plain initial REGISTRATION REQUEST carrying the
// advertised 5GS security capability (TS 24.501 §8.2.6, §9.11.3.54).
func (w *nsaWorld) registrationRequest() []byte {
	e, i := nsaCapOctets(w.ea, w.ia)
	pdu := []byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeRegistrationRequest), 0x71}
	pdu = append(pdu, nsaSUCIIdentity()...)
	return append(pdu, 0x2E, 0x04, e, i, 0x00, 0x00)
}

func (w *nsaWorld) handle(pdu []byte) error {
	err := w.h.HandleNASMessage(context.Background(), w.ue, pdu)
	w.lastErr = err
	return err
}

// ulProtect builds a UE uplink PDU: NIA2 MAC over SQN||payload (payload is the
// ciphertext when ciphered), NAS COUNT = ulCount, DIRECTION 0, then advances it.
func (w *nsaWorld) ulProtect(inner []byte, ciphered, newSC bool) ([]byte, error) {
	count := w.ulCount
	payload := inner
	sht := byte(nas.SecurityHeaderIntegrityProtected)
	switch {
	case ciphered && newSC:
		sht = byte(nas.SecurityHeaderIntegrityProtectedAndCipheredWithNewSC)
	case ciphered:
		sht = byte(nas.SecurityHeaderIntegrityProtectedAndCiphered)
	case newSC:
		sht = byte(nas.SecurityHeaderIntegrityProtectedWithNewSC)
	}
	if ciphered {
		var err error
		if payload, err = nsaUECipher(w.alg, w.knasenc, count, 0x00, inner); err != nil {
			return nil, err
		}
	}
	sqn := byte(count)
	macAlg := w.nia()
	macKey := w.knasint
	if w.macAlg != 0 {
		macAlg = w.macAlg
		macKey = kdf.KNASint(w.kamf, w.macAlg)
	}
	mac, err := nsaUEMAC(macAlg, macKey, count, 0x00, append([]byte{sqn}, payload...))
	if err != nil {
		return nil, err
	}
	pdu := append([]byte{nas.PDMobilityManagement, sht}, mac...)
	pdu = append(pdu, sqn)
	pdu = append(pdu, payload...)
	w.ulCount++
	return pdu, nil
}

func nsaPlain5GMM(mt nas.MessageType, body ...byte) []byte {
	return append([]byte{nas.PDMobilityManagement, 0x00, byte(mt)}, body...)
}

// driveToSMC sends the initial REGISTRATION REQUEST and the AUTHENTICATION
// RESPONSE and captures the SECURITY MODE COMMAND the AMF answers with.
func (w *nsaWorld) driveToSMC() error {
	if w.smc != nil {
		return nil
	}
	w.dlBase = len(w.sender.snapshot())
	if err := w.handle(w.registrationRequest()); err != nil {
		return fmt.Errorf("REGISTRATION REQUEST: %w", err)
	}
	dl := w.sender.snapshot()
	if len(dl) != w.dlBase+1 || len(dl[w.dlBase]) < 3 || dl[w.dlBase][2] != nsaMsgAR {
		return fmt.Errorf("expected one AUTHENTICATION REQUEST, DL = %x", dl[w.dlBase:])
	}
	resStar := append([]byte{0x2D, 0x10}, bytes.Repeat([]byte{0x5c}, 16)...)
	if err := w.handle(nsaPlain5GMM(nas.MsgTypeAuthenticationResponse, resStar...)); err != nil {
		return fmt.Errorf("AUTHENTICATION RESPONSE: %w", err)
	}
	dl = w.sender.snapshot()
	if len(dl) != w.dlBase+2 {
		return fmt.Errorf("expected a SECURITY MODE COMMAND after the AUTHENTICATION RESPONSE, got %d DL PDUs", len(dl)-w.dlBase)
	}
	w.smcMark = w.dlBase + 1
	w.smc = dl[w.smcMark]
	if len(w.smc) < 11 {
		return fmt.Errorf("SMC too short: %x", w.smc)
	}
	if w.smc[1]&0x0F != byte(nas.SecurityHeaderIntegrityProtectedWithNewSC) || w.smc[7] != nas.PDMobilityManagement ||
		w.smc[9] != nsaMsgSC {
		return fmt.Errorf("not a SECURITY MODE COMMAND with new security context: %x", w.smc)
	}
	w.intAlg = w.smc[10] & 0x0F
	w.deriveUEKeys(w.smc[10] >> 4)
	return nil
}

// completeSMC sends the SECURITY MODE COMPLETE protected with the new context,
// ciphered with the negotiated NEA.
func (w *nsaWorld) completeSMC() error {
	pdu, err := w.ulProtect(nsaPlain5GMM(nas.MsgTypeSecurityModeComplete), true, true)
	if err != nil {
		return err
	}
	return w.handle(pdu)
}

// ---- Background and givens ------------------------------------------------

func nsaBackgroundHandler() error {
	w := &nsaWorld{sender: &nsaSender{}, ausf: &nsaAUSF{}, smsf: &nsaSMSF{}, logs: &nsaSyncBuf{}}
	w.newHandler()
	nsaW = w
	return nil
}

func nsaStartRegistration(supi string) error {
	w := nsaW
	if w == nil || w.mgr == nil {
		return errors.New("AMF NAS handler not running")
	}
	if supi != nsaSUPI {
		return fmt.Errorf("scenario SUPI %q, step world is built for %q", supi, nsaSUPI)
	}
	w.ue = w.newUE(1)
	return nil
}

func nsaCipheringOrderDefault(order string) error { return nsaCipheringOrder(order) }

func nsaCipheringOrder(order string) error {
	ids, err := procedures.ParseCipheringOrder(order)
	if err != nil {
		return fmt.Errorf("order %q: %w", order, err)
	}
	nsaW.reg.WithCipheringOrder(ids)
	return nil
}

var nsaAlgTok = regexp.MustCompile(`(EA|IA)(\d)`)

func nsaCapability(ea, ia string) error {
	w := nsaW
	w.ea, w.ia = [4]bool{}, [4]bool{}
	for _, m := range nsaAlgTok.FindAllStringSubmatch(ea, -1) {
		n, _ := strconv.Atoi(m[2])
		if m[1] != "EA" || n > 3 {
			return fmt.Errorf("bad EA token %q", m[0])
		}
		w.ea[n] = true
	}
	for _, m := range nsaAlgTok.FindAllStringSubmatch(ia, -1) {
		n, _ := strconv.Atoi(m[2])
		if m[1] != "IA" || n > 3 {
			return fmt.Errorf("bad IA token %q", m[0])
		}
		w.ia[n] = true
	}
	return nil
}

// ---- SMC selection --------------------------------------------------------

func nsaSendSMC() error { return nsaW.driveToSMC() }

func nsaSelectedCipheringIs(want int) error {
	w := nsaW
	if w.smc == nil {
		return errors.New("no SECURITY MODE COMMAND was sent")
	}
	octet := w.smc[10]
	if got := int(octet >> 4); got != want {
		return fmt.Errorf("Selected NAS security algorithms octet %#02x: ciphering field %d, want %d", octet, got, want)
	}
	return nil
}

func nsaSMCIdenticalToLegacy() error {
	w := nsaW
	e, i := nsaCapOctets(w.ea, w.ia)
	smc := &nas.SecurityModeCommand{
		SelectedNASSecurityAlgorithms: nas.NASSecurityAlgorithms{CipheringAlgorithmID: 2, IntegrityAlgorithmID: 2},
		NGKSI:                         nas.NGKSI{KeySetIdentifier: w.ue.SecurityCtx.NGKSI, Type: 0},
		ReplayedUESecurityCapabilities: nas.UESecurityCapability{
			EA0: w.ea[0], EA1: w.ea[1], EA2: w.ea[2], EA3: w.ea[3],
			IA0: w.ia[0], IA1: w.ia[1], IA2: w.ia[2], IA3: w.ia[3],
			Raw: []byte{e, i, 0x00, 0x00},
		},
	}
	imeisv, rinmr := nas.IMEISVRequested, nas.Additional5GSecInfoRINMR
	smc.IMEISVRequest, smc.Additional5GSecurityInfo = &imeisv, &rinmr
	plain, err := nas.Encode(&nas.Message{
		Header: nas.Header{ExtendedProtocolDiscriminator: nas.PDMobilityManagement, MessageType: nas.MsgTypeSecurityModeCommand},
		Body:   smc,
	})
	if err != nil {
		return err
	}
	// Legacy protection: NIA2 MAC over SQN(0)||plain, DL COUNT 0, DIRECTION 1,
	// SHT 3 (integrity protected with new security context).
	mac, err := nia.NIA2(w.knasint, 0, 0x01, 0x01, append([]byte{0}, plain...))
	if err != nil {
		return err
	}
	want := append([]byte{nas.PDMobilityManagement, byte(nas.SecurityHeaderIntegrityProtectedWithNewSC)}, mac...)
	want = append(append(want, 0x00), plain...)
	if !bytes.Equal(w.smc, want) {
		return fmt.Errorf("SECURITY MODE COMMAND differs from the legacy golden\n got  %x\n want %x", w.smc, want)
	}
	if w.smc[10] != 0x22 {
		return fmt.Errorf("Selected NAS security algorithms octet %#02x, legacy is 0x22", w.smc[10])
	}
	return nil
}

func nsaUECompletesSecurityMode() error {
	w := nsaW
	if err := w.driveToSMC(); err != nil {
		return err
	}
	if err := w.completeSMC(); err != nil {
		return fmt.Errorf("SECURITY MODE COMPLETE: %w", err)
	}
	return nil
}

// ---- Registration Accept (downlink) ---------------------------------------

func (w *nsaWorld) findAccept() error {
	dl := w.sender.snapshot()
	for i := len(dl) - 1; i > w.smcMark; i-- {
		if len(dl[i]) > 7 && dl[i][1]&0x0F == byte(nas.SecurityHeaderIntegrityProtectedAndCiphered) {
			w.accept, w.acceptDLAt = dl[i], i
			return nil
		}
	}
	return fmt.Errorf("no integrity protected and ciphered DL NAS PDU after the SMC (DL = %d PDUs)", len(dl))
}

func nsaAMFSendsRegistrationAccept() error {
	if err := nsaW.findAccept(); err != nil {
		return fmt.Errorf("the AMF did not send the REGISTRATION ACCEPT: %w", err)
	}
	return nil
}

func nsaAcceptSHT(want int) error {
	if nsaW.accept == nil {
		return errors.New("no REGISTRATION ACCEPT captured")
	}
	if got := int(nsaW.accept[1] & 0x0F); got != want {
		return fmt.Errorf("REGISTRATION ACCEPT security header type %d, want %d", got, want)
	}
	return nil
}

// ueDecipherDL deciphers a DL PDU on the UE side with the named NEA.
func (w *nsaWorld) ueDecipherDL(pdu []byte, alg byte) ([]byte, error) {
	if len(pdu) < 8 {
		return nil, fmt.Errorf("DL PDU too short: %x", pdu)
	}
	count := uint32(pdu[6]) // the first DL messages: NAS COUNT overflow is still 0
	return nsaUECipher(alg, w.knasenc, count, 0x01, pdu[7:])
}

func nsaUEDecipherYieldsAccept(name string) error {
	w := nsaW
	alg, err := nsaNEAByName(name)
	if err != nil {
		return err
	}
	if w.accept == nil {
		return errors.New("no REGISTRATION ACCEPT captured")
	}
	if alg != w.alg {
		return fmt.Errorf("step names %s but the SMC selected NEA%d", name, w.alg)
	}
	plain, err := w.ueDecipherDL(w.accept, alg)
	if err != nil {
		return err
	}
	if len(plain) < 3 || plain[0] != nas.PDMobilityManagement || plain[1] != 0x00 || plain[2] != nsaMsgRA {
		return fmt.Errorf("UE-side %s deciphering gave %x, want a plain 5GMM REGISTRATION ACCEPT (7e 00 42 ...)", name, plain)
	}
	if _, err := nas.Decode(plain); err != nil {
		return fmt.Errorf("deciphered REGISTRATION ACCEPT does not decode: %w", err)
	}
	return nil
}

func nsaMACOverCiphertext() error {
	w := nsaW
	if w.accept == nil {
		return errors.New("no REGISTRATION ACCEPT captured")
	}
	ok, err := nia.Verify(w.knasint, uint32(w.accept[6]), 0x01, 0x01, w.accept[6:], w.accept[2:6])
	if err != nil || !ok {
		return fmt.Errorf("NAS MAC is not NIA2 over SQN||ciphertext (ok=%v err=%v)", ok, err)
	}
	return nil
}

// ---- NEA3 operator list: UL decipher --------------------------------------

func nsaUESendsCipheredSMCComplete(name string) error {
	w := nsaW
	alg, err := nsaNEAByName(name)
	if err != nil {
		return err
	}
	if err := w.driveToSMC(); err != nil {
		return err
	}
	if w.alg != alg {
		return fmt.Errorf("step names %s but the SMC selected NEA%d", name, w.alg)
	}
	return w.completeSMC()
}

func nsaAMFDecipheredSMCComplete(name string) error {
	w := nsaW
	if w.lastErr != nil {
		return fmt.Errorf("AMF rejected the SECURITY MODE COMPLETE ciphered with %s: %w", name, w.lastErr)
	}
	if w.ue.SecurityCtx.UplinkCount != 1 {
		return fmt.Errorf("UL NAS COUNT %d after the SECURITY MODE COMPLETE, want 1", w.ue.SecurityCtx.UplinkCount)
	}
	if got := w.ue.RegStage(); got != amfctx.RegStageAcceptSent {
		return fmt.Errorf("registration stage %s, want the REGISTRATION ACCEPT sent (SMC COMPLETE not processed)", got)
	}
	return w.findAccept()
}

func nsaUESendsCipheredULNASTransport(name string) error {
	w := nsaW
	alg, err := nsaNEAByName(name)
	if err != nil {
		return err
	}
	if alg != w.alg {
		return fmt.Errorf("step names %s but the SMC selected NEA%d", name, w.alg)
	}
	return w.sendSMSTransport(true)
}

// sendSMSTransport sends a UL NAS TRANSPORT (payload container type SMS) whose
// payload is a marker: the SMSF mock sees it only when the AMF deciphers the PDU.
func (w *nsaWorld) sendSMSTransport(ciphered bool) error {
	body := []byte{0x02, 0x00, byte(len(nsaSMSMarker))}
	body = append(body, nsaSMSMarker...)
	pdu, err := w.ulProtect(nsaPlain5GMM(nas.MsgTypeULNASTransport, body...), ciphered, false)
	if err != nil {
		return err
	}
	return w.handle(pdu)
}

var nsaSMSMarker = []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03}

func nsaAMFDecipheredULTransport(name string) error {
	w := nsaW
	if w.lastErr != nil {
		return fmt.Errorf("AMF failed on the UL NAS TRANSPORT ciphered with %s: %w", name, w.lastErr)
	}
	got := w.smsf.got()
	if len(got) != 1 || !bytes.Equal(got[0], nsaSMSMarker) {
		return fmt.Errorf("SMSF received %x, want exactly the plain payload container %x", got, nsaSMSMarker)
	}
	return nil
}

// ---- NAS message container (TS 24.501 §4.4.6) -----------------------------

func nsaSMCSelectedCipheringAlgorithm(nea int) error {
	w := nsaW
	if err := w.driveToSMC(); err != nil {
		return err
	}
	if err := nsaSelectedCipheringIs(nea); err != nil {
		return err
	}
	if err := w.completeSMC(); err != nil {
		return fmt.Errorf("SECURITY MODE COMPLETE: %w", err)
	}
	if err := w.findAccept(); err != nil {
		return err
	}
	// REGISTRATION COMPLETE: the UE is now 5GMM-REGISTERED with this context.
	pdu, err := w.ulProtect(nsaPlain5GMM(nas.MsgTypeRegistrationComplete), true, false)
	if err != nil {
		return err
	}
	if err := w.handle(pdu); err != nil {
		return fmt.Errorf("REGISTRATION COMPLETE: %w", err)
	}
	if w.ue.State != amfctx.GMMRegistered {
		return fmt.Errorf("UE state %v after REGISTRATION COMPLETE, want 5GMM-REGISTERED", w.ue.State)
	}
	w.ausfBase = w.ausf.count()
	w.dlBase = len(w.sender.snapshot())
	return nil
}

// nsaGUTIIdentity is a 5G-GUTI mobile identity LV-E (TS 24.501 §9.11.3.4).
func nsaGUTIIdentity() []byte {
	v := []byte{0xF2, 0x00, 0xF1, 0x10, 0x02, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01}
	return append([]byte{0x00, byte(len(v))}, v...)
}

var nsaContainerNSSAI = []byte{0x2F, 0x02, 0x01, 0x01} // Requested NSSAI: SST 1

func nsaUESendsMobilityUpdateWithContainer(name string) error {
	w := nsaW
	alg, err := nsaNEAByName(name)
	if err != nil {
		return err
	}
	if alg != w.alg {
		return fmt.Errorf("step names %s but the SMC selected NEA%d", name, w.alg)
	}
	// Full REGISTRATION REQUEST (mobility) carrying the non-cleartext IEs.
	inner := []byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeRegistrationRequest),
		byte(w.ue.SecurityCtx.NGKSI<<4) | byte(nas.RegistrationTypeMobility)}
	inner = append(inner, nsaGUTIIdentity()...)
	inner = append(inner, nsaContainerNSSAI...)
	// The container is ciphered with the NAS COUNT of the outer message
	// (TS 24.501 §4.4.6); the outer message itself is integrity protected only.
	ct, err := nsaUECipher(alg, w.knasenc, w.ulCount, 0x00, inner)
	if err != nil {
		return err
	}
	outer := []byte{nas.PDMobilityManagement, 0x00, byte(nas.MsgTypeRegistrationRequest),
		byte(w.ue.SecurityCtx.NGKSI<<4) | byte(nas.RegistrationTypeMobility)}
	outer = append(outer, nsaGUTIIdentity()...)
	outer = append(outer, 0x71, byte(len(ct)>>8), byte(len(ct)))
	outer = append(outer, ct...)
	pdu, err := w.ulProtect(outer, false, false)
	if err != nil {
		return err
	}
	return w.handle(pdu)
}

func nsaAMFDecipheredContainer(name string) error {
	w := nsaW
	if w.lastErr != nil {
		return fmt.Errorf("AMF failed on the mobility REGISTRATION REQUEST: %w", w.lastErr)
	}
	if strings.Contains(w.logs.String(), "cannot be deciphered") {
		return fmt.Errorf("AMF logged that the NAS message container cannot be deciphered with %s", name)
	}
	return nil
}

func nsaAMFContinuesWithContainerRequest() error {
	w := nsaW
	if len(w.ue.RequestedNSSAI) != 1 || w.ue.RequestedNSSAI[0].SST != 1 {
		return fmt.Errorf("Requested NSSAI %+v, want the single S-NSSAI SST 1 carried only inside the container", w.ue.RequestedNSSAI)
	}
	dl := w.sender.snapshot()
	if len(dl) != w.dlBase+1 {
		return fmt.Errorf("expected exactly one DL NAS PDU (REGISTRATION ACCEPT), got %d", len(dl)-w.dlBase)
	}
	pdu := dl[w.dlBase]
	plain, err := w.ueDecipherDL(pdu, w.alg)
	if err != nil {
		return err
	}
	if len(plain) < 3 || plain[0] != nas.PDMobilityManagement || plain[2] != nsaMsgRA {
		return fmt.Errorf("DL PDU deciphered to %x, want a REGISTRATION ACCEPT", plain)
	}
	return nil
}

func nsaNoFreshAuthentication() error {
	w := nsaW
	if got := w.ausf.count(); got != w.ausfBase {
		return fmt.Errorf("AUSF InitiateAuth called %d more time(s): a fresh authentication was started", got-w.ausfBase)
	}
	for _, p := range w.sender.snapshot()[w.dlBase:] {
		if len(p) > 2 && p[2] == nsaMsgAR {
			return fmt.Errorf("AUTHENTICATION REQUEST sent: %x", p)
		}
		if len(p) > 9 && p[9] == nsaMsgSC {
			return fmt.Errorf("SECURITY MODE COMMAND sent: %x", p)
		}
	}
	return nil
}

// ---- UE with no common EA -------------------------------------------------

func nsaEvaluateUESecurityCapability() error {
	w := nsaW
	w.dlBase = len(w.sender.snapshot())
	_ = w.handle(w.registrationRequest())
	return nil
}

func nsaRegistrationRejectWithCause(cause int, text string) error {
	w := nsaW
	dl := w.sender.snapshot()[w.dlBase:]
	if len(dl) == 0 {
		return errors.New("no DL NAS message was sent")
	}
	p := dl[0]
	if len(p) < 4 || p[0] != nas.PDMobilityManagement || p[1] != 0x00 || p[2] != nsaMsgRR || int(p[3]) != cause {
		return fmt.Errorf("first DL NAS PDU %x, want a plain REGISTRATION REJECT with 5GMM cause %d (%s)", p, cause, text)
	}
	return nil
}

func nsaNoSMCSent() error {
	w := nsaW
	for _, p := range w.sender.snapshot() {
		if len(p) > 9 && p[9] == nsaMsgSC || len(p) > 2 && p[2] == nsaMsgSC {
			return fmt.Errorf("a SECURITY MODE COMMAND was sent: %x", p)
		}
		if len(p) > 2 && p[2] == nsaMsgAR {
			return fmt.Errorf("an AUTHENTICATION REQUEST was sent: %x", p)
		}
	}
	if w.ausf.count() != 0 {
		return fmt.Errorf("AUSF was contacted %d time(s)", w.ausf.count())
	}
	return nil
}

// ---- configuration --------------------------------------------------------

func nsaLoadConfig(order string) error {
	_ = os.Unsetenv(procedures.EnvCipheringOrder)
	w := nsaW
	if w == nil {
		w = &nsaWorld{}
		nsaW = w
	}
	w.cfgOrder, w.cfgErr = procedures.ResolveCipheringOrder(order)
	return nil
}

func nsaLoadConfigEnv(value string) error {
	if err := os.Setenv(procedures.EnvCipheringOrder, value); err != nil {
		return err
	}
	w := nsaW
	if w == nil {
		w = &nsaWorld{}
		nsaW = w
	}
	w.cfgOrder, w.cfgErr = procedures.ResolveCipheringOrder("")
	return nil
}

func nsaConfigErrorNaming(key string) error {
	w := nsaW
	if w.cfgErr == nil {
		return fmt.Errorf("configuration load succeeded with order %v, want an error", w.cfgOrder)
	}
	if !strings.Contains(w.cfgErr.Error(), key) {
		return fmt.Errorf("error %q does not name %q", w.cfgErr, key)
	}
	return nil
}

func nsaAMFDoesNotStart() error {
	w := nsaW
	if w.cfgErr == nil || w.cfgOrder != nil {
		return fmt.Errorf("startup would continue: order=%v err=%v", w.cfgOrder, w.cfgErr)
	}
	return nil
}

func nsaEffectiveOrder(list string) error {
	w := nsaW
	if w.cfgErr != nil {
		return fmt.Errorf("configuration load failed: %w", w.cfgErr)
	}
	want, err := procedures.ParseCipheringOrder(list)
	if err != nil {
		return err
	}
	if !bytes.Equal(w.cfgOrder, want) {
		return fmt.Errorf("effective ciphering order %v, want %v", w.cfgOrder, want)
	}
	return nil
}

// nsaLogsEffectiveOrder cannot be observed in this package: the startup log is
// emitted by cmd/amf main (package main, not importable here).
func nsaLogsEffectiveOrder() error {
	return godog.ErrPending
}

// ---- unknown CipheringAlgID ----------------------------------------------

func nsaRegisteredUEWithAlg(alg int) error {
	w := nsaW
	ue := w.newUE(2)
	w.mgr.SetSUPI(ue, nsaSUPI)
	w.ue = ue
	w.deriveUEKeys(byte(alg % 4))
	ue.SecurityCtx = amfctx.SecurityContext{
		Active: true, NGKSI: 1, IntegrityAlgID: 2, CipheringAlgID: byte(alg),
		KNASint: w.knasint, KNASenc: w.knasenc, KAMF: w.kamf,
	}
	ue.Lock()
	ue.State = amfctx.GMMRegistered
	ue.Unlock()
	w.alg = 2 // the UE (wrongly, or an attacker) ciphers uplink with NEA2
	w.knasenc = kdf.KNASenc(w.kamf, 2)
	return nil
}

func nsaTrySendCipheredDL() error {
	w := nsaW
	w.dlBase = len(w.sender.snapshot())
	w.lastErr = w.h.SendNetworkDeregistration(context.Background(), w.ue, 0x09, 0, false)
	return nil
}

func nsaAMFReturnsError(text string) error {
	w := nsaW
	if w.lastErr == nil || !strings.Contains(w.lastErr.Error(), text) {
		return fmt.Errorf("error %v, want one containing %q", w.lastErr, text)
	}
	return nil
}

func nsaNoNASPDUSent() error {
	w := nsaW
	if n := len(w.sender.snapshot()) - w.dlBase; n != 0 {
		return fmt.Errorf("%d NAS PDU(s) were sent to the gNB", n)
	}
	if w.ue.SecurityCtx.DownlinkCount != 0 {
		return fmt.Errorf("DL NAS COUNT advanced to %d", w.ue.SecurityCtx.DownlinkCount)
	}
	return nil
}

func nsaLogsResult(result string) error {
	if !strings.Contains(nsaW.logs.String(), `"result":"`+result+`"`) {
		return fmt.Errorf("no log line with result=%q (docs/procedures/nas-security-algorithms.md §5)", result)
	}
	return nil
}

func nsaNotCipheredNEA2NorPlain() error {
	w := nsaW
	if len(w.sender.snapshot()) != w.dlBase {
		return errors.New("a PDU was sent")
	}
	if w.ue.State != amfctx.GMMRegistered {
		return fmt.Errorf("UE state moved to %v although nothing was sent", w.ue.State)
	}
	return nil
}

func nsaUESendsCipheredULWithSHT2(sht int) error {
	w := nsaW
	if sht != 2 {
		return fmt.Errorf("only SHT 2 is bound, got %d", sht)
	}
	// MAC valid, body ciphered with NEA2: any NEA2 fallback would process it.
	// The AMF's error is the subject of the next step, not a failure here.
	w.dlBase = len(w.sender.snapshot())
	_ = w.sendSMSTransport(true)
	return nil
}

func nsaAMFReturnsErrorNoProcess(text string) error {
	w := nsaW
	if err := nsaAMFReturnsError(text); err != nil {
		return err
	}
	if got := w.smsf.got(); len(got) != 0 {
		return fmt.Errorf("the message was processed: SMSF received %x", got)
	}
	if w.ue.SecurityCtx.UplinkCount != 0 {
		return fmt.Errorf("UL NAS COUNT advanced to %d", w.ue.SecurityCtx.UplinkCount)
	}
	return nil
}

func nsaNotDecipheredWithNEA2() error {
	w := nsaW
	if got := w.smsf.got(); len(got) != 0 {
		return fmt.Errorf("the NEA2-ciphered message was deciphered and relayed: %x", got)
	}
	return nil
}

// ---- registration ---------------------------------------------------------

func initNASSecurityAlgorithmsSteps(sc *godog.ScenarioContext) {
	sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
		nsaW = nil
		_ = os.Unsetenv(procedures.EnvCipheringOrder)
		_ = os.Unsetenv(procedures.EnvIntegrityOrder)
		return ctx, nil
	})
	sc.After(func(ctx context.Context, _ *godog.Scenario, _ error) (context.Context, error) {
		if w := nsaW; w != nil && w.ue != nil {
			w.ue.ClearRegProc() // stop T3560/T3550 retransmission timers
		}
		_ = os.Unsetenv(procedures.EnvCipheringOrder)
		_ = os.Unsetenv(procedures.EnvIntegrityOrder)
		return ctx, nil
	})

	sc.Step(`^the AMF NAS handler is running with an AUSF mock returning a KAMF$`, nsaBackgroundHandler)
	sc.Step(`^a UE "([^"]+)" starts an initial registration over 3GPP access$`, nsaStartRegistration)
	sc.Step(`^the AMF ciphering order is the default "([^"]*)"$`, nsaCipheringOrderDefault)
	sc.Step(`^the AMF ciphering order is "([^"]*)"$`, nsaCipheringOrder)
	sc.Step(`^the UE security capability advertises (.+?)(?: only)? and (IA.+)$`, nsaCapability)

	sc.Step(`^the AMF sends the SECURITY MODE COMMAND$`, nsaSendSMC)
	sc.Step(`^the Selected NAS security algorithms IE ciphering field is (\d)$`, nsaSelectedCipheringIs)
	sc.Step(`^the SECURITY MODE COMMAND bytes are identical to the legacy golden SECURITY MODE COMMAND$`, nsaSMCIdenticalToLegacy)
	sc.Step(`^the UE completes the security mode procedure$`, nsaUECompletesSecurityMode)
	sc.Step(`^the AMF sends the REGISTRATION ACCEPT downlink$`, nsaAMFSendsRegistrationAccept)
	sc.Step(`^the REGISTRATION ACCEPT security header type is (\d) \(integrity protected and ciphered\)$`, nsaAcceptSHT)
	sc.Step(`^the UE-side deciphering with (NEA\d), KNASenc, the DL NAS COUNT, BEARER 0x01 and DIRECTION 1 yields the plain 5GMM REGISTRATION ACCEPT$`, nsaUEDecipherYieldsAccept)
	sc.Step(`^the NAS MAC is computed over the ciphertext$`, nsaMACOverCiphertext)

	sc.Step(`^the UE sends a SECURITY MODE COMPLETE ciphered with (NEA\d), DIRECTION 0 and integrity protected over the ciphertext$`, nsaUESendsCipheredSMCComplete)
	sc.Step(`^the AMF deciphers the SECURITY MODE COMPLETE with (NEA\d) and accepts it$`, nsaAMFDecipheredSMCComplete)
	sc.Step(`^the UE sends a ciphered UL NAS TRANSPORT with (NEA\d)$`, nsaUESendsCipheredULNASTransport)
	sc.Step(`^the AMF deciphers it with (NEA\d) to the plain 5GMM message$`, nsaAMFDecipheredULTransport)

	sc.Step(`^the SECURITY MODE COMMAND selected ciphering algorithm (\d)$`, nsaSMCSelectedCipheringAlgorithm)
	sc.Step(`^the UE sends a mobility REGISTRATION REQUEST, integrity protected, whose NAS message container carries the full REGISTRATION REQUEST ciphered with (NEA\d)$`, nsaUESendsMobilityUpdateWithContainer)
	sc.Step(`^the AMF deciphers the NAS message container with (NEA\d)$`, nsaAMFDecipheredContainer)
	sc.Step(`^the AMF continues the registration with the REGISTRATION REQUEST from the container$`, nsaAMFContinuesWithContainerRequest)
	sc.Step(`^no fresh authentication is started$`, nsaNoFreshAuthentication)

	sc.Step(`^the AMF evaluates the UE security capability$`, nsaEvaluateUESecurityCapability)
	sc.Step(`^the AMF sends a REGISTRATION REJECT with 5GMM cause (\d+) "([^"]*)"$`, nsaRegistrationRejectWithCause)
	sc.Step(`^no SECURITY MODE COMMAND is sent$`, nsaNoSMCSent)

	sc.Step(`^the AMF configuration is loaded with nas_security\.ciphering_order "([^"]*)"$`, nsaLoadConfig)
	sc.Step(`^the AMF configuration is loaded with env AMF_NAS_CIPHERING_ORDER "([^"]*)"$`, nsaLoadConfigEnv)
	sc.Step(`^the configuration load returns an error naming "([^"]*)"$`, nsaConfigErrorNaming)
	sc.Step(`^the AMF does not start$`, nsaAMFDoesNotStart)
	sc.Step(`^the effective ciphering order is (NEA\d(?:, NEA\d)*)$`, nsaEffectiveOrder)
	sc.Step(`^the AMF logs the effective NAS ciphering order at startup$`, nsaLogsEffectiveOrder)

	sc.Step(`^a registered UE whose NAS security context has CipheringAlgID (\d+)$`, nsaRegisteredUEWithAlg)
	sc.Step(`^the AMF tries to send a ciphered downlink NAS message$`, nsaTrySendCipheredDL)
	sc.Step(`^the AMF returns an error "([^"]*)"$`, nsaAMFReturnsError)
	sc.Step(`^no NAS PDU is sent to the gNB$`, nsaNoNASPDUSent)
	sc.Step(`^the AMF logs result "([^"]*)"$`, nsaLogsResult)
	sc.Step(`^the message is not ciphered with NEA2 and not sent in plaintext$`, nsaNotCipheredNEA2NorPlain)
	sc.Step(`^the UE sends a ciphered UL NAS message with SHT (\d)$`, nsaUESendsCipheredULWithSHT2)
	sc.Step(`^the AMF returns an error "([^"]*)" and does not process the message$`, nsaAMFReturnsErrorNoProcess)
	sc.Step(`^the AMF does not decipher it with NEA2$`, nsaNotDecipheredWithNEA2)
	sc.Step(`^the AMF integrity order is the default "([^"]*)"$`, nsaIntegrityOrder)
	sc.Step(`^the AMF integrity order is "([^"]*)"$`, nsaIntegrityOrder)
	sc.Step(`^the Selected NAS security algorithms IE integrity field is (\d)$`, nsaSelectedIntegrityIs)
	sc.Step(`^the SECURITY MODE COMMAND NAS-MAC verifies with (NIA\d) and not with any other NIA$`, nsaSMCMACVerifiesWith)
	sc.Step(`^the AMF accepts the SECURITY MODE COMPLETE integrity protected with (NIA\d)$`, nsaAMFAcceptsSMCCompleteNIA)
	sc.Step(`^the REGISTRATION ACCEPT NAS-MAC verifies with (NIA\d) and not with NIA2$`, nsaAcceptMACVerifiesWith)
	sc.Step(`^the UE sends a UL NAS TRANSPORT whose NAS-MAC is computed with (NIA\d)$`, nsaUESendsULWithMACAlg)
	sc.Step(`^the AMF discards the message as an integrity failure and does not process it$`, nsaAMFDiscardedIntegrity)
	sc.Step(`^the UL NAS COUNT is not advanced$`, nsaULCountNotAdvanced)
	sc.Step(`^the AMF configuration is loaded with nas_security\.integrity_order "([^"]*)"$`, nsaLoadIntegrityConfig)
	sc.Step(`^the AMF configuration is loaded with env AMF_NAS_INTEGRITY_ORDER "([^"]*)"$`, nsaLoadIntegrityConfigEnv)
	sc.Step(`^the effective integrity order is (NIA\d(?:, NIA\d)*)$`, nsaEffectiveIntegrityOrder)

	sc.Step(`^the AMF debug flag security\.null_ciphering is (enabled|disabled)$`, nsaNullCipheringFlag)
	sc.Step(`^the Selected NAS security algorithms IE octet is 0x([0-9A-Fa-f]{2})$`, nsaSelectedOctetIs)
	sc.Step(`^the AMF logs a WARN that null_ciphering was requested but the UE does not support 5G-EA0$`, nsaLogsNullCipheringWarn)
	sc.Step(`^NEA0 is not selected$`, nsaNEA0NotSelected)
	sc.Step(`^the AMF logs no null_ciphering WARN$`, nsaLogsNoNullCipheringWarn)
}

// ---- AMF-009: debug security.null_ciphering --------------------------------

const nsaNullWarnMsg = "null_ciphering set but UE does not advertise 5G-EA0"

func nsaNullCipheringFlag(state string) error {
	if nsaW == nil || nsaW.reg == nil {
		return errors.New("AMF NAS handler not running")
	}
	nsaW.reg.WithNullSecurity(state == "enabled")
	return nil
}

func nsaSelectedOctetIs(hexs string) error {
	w := nsaW
	if w.smc == nil {
		return errors.New("no SECURITY MODE COMMAND was sent")
	}
	want, err := strconv.ParseUint(hexs, 16, 8)
	if err != nil {
		return err
	}
	if w.smc[10] != byte(want) {
		return fmt.Errorf("Selected NAS security algorithms octet %#02x, want %#02x", w.smc[10], want)
	}
	return nil
}

// nsaNullWarnRecords returns the WARN records of the null_ciphering fallback.
func nsaNullWarnRecords() ([]map[string]any, error) {
	var out []map[string]any
	for _, line := range strings.Split(nsaW.logs.String(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		msg, _ := rec["msg"].(string)
		if rec["level"] == "WARN" && strings.Contains(msg, "null_ciphering") {
			out = append(out, rec)
		}
	}
	return out, nil
}

func nsaLogsNullCipheringWarn() error {
	recs, _ := nsaNullWarnRecords()
	if len(recs) != 1 {
		return fmt.Errorf("want exactly one null_ciphering WARN, got %d in logs", len(recs))
	}
	r := recs[0]
	if msg, _ := r["msg"].(string); !strings.Contains(msg, nsaNullWarnMsg) {
		return fmt.Errorf("WARN message %q does not report the missing 5G-EA0", msg)
	}
	if r["cipher_alg"] != float64(nsaW.alg) {
		return fmt.Errorf("WARN cipher_alg %v, want %d (selected NEA)", r["cipher_alg"], nsaW.alg)
	}
	if r["interface"] != "N1" || r["direction"] != "OUT" || r["spec_ref"] == nil {
		return fmt.Errorf("WARN lacks interface N1 / direction OUT / spec_ref: %v", r)
	}
	return nil
}

func nsaLogsNoNullCipheringWarn() error {
	recs, _ := nsaNullWarnRecords()
	if len(recs) != 0 {
		return fmt.Errorf("unexpected null_ciphering WARN: %v", recs[0])
	}
	return nil
}

func nsaNEA0NotSelected() error {
	w := nsaW
	if w.smc == nil {
		return nil // no SMC at all (registration rejected): NEA0 cannot have been selected
	}
	if w.smc[10]>>4 == 0 {
		return fmt.Errorf("NEA0 selected (octet %#02x) although the UE did not advertise EA0", w.smc[10])
	}
	return nil
}

// ---- SEC-007: NAS integrity (NIA1 / NIA2 / NIA3) --------------------------

func nsaIntegrityOrder(order string) error {
	ids, err := procedures.ParseIntegrityOrder(order)
	if err != nil {
		return fmt.Errorf("order %q: %w", order, err)
	}
	nsaW.reg.WithIntegrityOrder(ids)
	return nil
}

func nsaSelectedIntegrityIs(want int) error {
	w := nsaW
	if w.smc == nil {
		return errors.New("no SECURITY MODE COMMAND was sent")
	}
	if got := int(w.smc[10] & 0x0F); got != want {
		return fmt.Errorf("Selected NAS security algorithms octet %#02x: integrity field %d, want %d", w.smc[10], got, want)
	}
	return nil
}

// nsaSMCMACVerifiesWith checks the SMC NAS-MAC (DL COUNT 0, DIRECTION 1) with the
// named NIA and that no other NIA yields the same MAC.
func nsaSMCMACVerifiesWith(name string) error {
	w := nsaW
	want, err := nsaNIAByName(name)
	if err != nil {
		return err
	}
	if w.smc == nil {
		return errors.New("no SECURITY MODE COMMAND was sent")
	}
	if w.intAlg != want {
		return fmt.Errorf("step names %s but the SMC selected NIA%d", name, w.intAlg)
	}
	for a := byte(1); a <= 3; a++ {
		mac, err := nsaUEMAC(a, kdf.KNASint(w.kamf, a), 0, 0x01, w.smc[6:])
		if err != nil {
			return err
		}
		match := bytes.Equal(mac, w.smc[2:6])
		if a == want && !match {
			return fmt.Errorf("SMC NAS-MAC %x does not verify with NIA%d (expected %x)", w.smc[2:6], a, mac)
		}
		if a != want && match {
			return fmt.Errorf("SMC NAS-MAC %x also verifies with NIA%d: not selected-algorithm specific", w.smc[2:6], a)
		}
	}
	return nil
}

func nsaAMFAcceptsSMCCompleteNIA(name string) error {
	w := nsaW
	alg, err := nsaNIAByName(name)
	if err != nil {
		return err
	}
	if err := w.driveToSMC(); err != nil {
		return err
	}
	if w.intAlg != alg {
		return fmt.Errorf("step names %s but the SMC selected NIA%d", name, w.intAlg)
	}
	if err := w.completeSMC(); err != nil {
		return fmt.Errorf("AMF rejected the SECURITY MODE COMPLETE MAC-ed with %s: %w", name, err)
	}
	if w.ue.SecurityCtx.UplinkCount != 1 {
		return fmt.Errorf("UL NAS COUNT %d after the SECURITY MODE COMPLETE, want 1", w.ue.SecurityCtx.UplinkCount)
	}
	if got := w.ue.RegStage(); got != amfctx.RegStageAcceptSent {
		return fmt.Errorf("registration stage %s, want the REGISTRATION ACCEPT sent (SMC COMPLETE not accepted)", got)
	}
	return w.findAccept()
}

func nsaAcceptMACVerifiesWith(name string) error {
	w := nsaW
	want, err := nsaNIAByName(name)
	if err != nil {
		return err
	}
	if w.accept == nil {
		return errors.New("no REGISTRATION ACCEPT captured")
	}
	if w.intAlg != want {
		return fmt.Errorf("step names %s but the SMC selected NIA%d", name, w.intAlg)
	}
	count := uint32(w.accept[6])
	mac, err := nsaUEMAC(want, w.knasint, count, 0x01, w.accept[6:])
	if err != nil {
		return err
	}
	if !bytes.Equal(mac, w.accept[2:6]) {
		return fmt.Errorf("REGISTRATION ACCEPT NAS-MAC %x does not verify with %s (expected %x)", w.accept[2:6], name, mac)
	}
	if want != 2 {
		if other, err := nsaUEMAC(2, kdf.KNASint(w.kamf, 2), count, 0x01, w.accept[6:]); err == nil && bytes.Equal(other, w.accept[2:6]) {
			return errors.New("REGISTRATION ACCEPT NAS-MAC also verifies with NIA2")
		}
	}
	return nil
}

// nsaUESendsULWithMACAlg sends an integrity-only UL NAS TRANSPORT MAC-ed with a
// NIA other than the selected one; the AMF's reaction is asserted by later steps.
func nsaUESendsULWithMACAlg(name string) error {
	w := nsaW
	alg, err := nsaNIAByName(name)
	if err != nil {
		return err
	}
	if alg == w.nia() {
		return fmt.Errorf("%s is the selected NIA; the negative step needs a different one", name)
	}
	w.dlBase = len(w.sender.snapshot())
	w.macAlg = alg
	defer func() { w.macAlg = 0 }()
	_ = w.sendSMSTransport(false)
	return nil
}

func nsaAMFDiscardedIntegrity() error {
	w := nsaW
	if w.lastErr != nil {
		return fmt.Errorf("AMF returned %v; an integrity failure after a verified exchange is a silent discard", w.lastErr)
	}
	if got := w.smsf.got(); len(got) != 0 {
		return fmt.Errorf("the message was processed: SMSF received %x", got)
	}
	if !strings.Contains(w.logs.String(), "uplink NAS message discarded") {
		return errors.New(`no "uplink NAS message discarded" log line`)
	}
	return nil
}

func nsaULCountNotAdvanced() error {
	if got := nsaW.ue.SecurityCtx.UplinkCount; got != 1 {
		return fmt.Errorf("UL NAS COUNT %d, want 1 (only the SECURITY MODE COMPLETE was accepted)", got)
	}
	return nil
}

func nsaLoadIntegrityConfig(order string) error {
	_ = os.Unsetenv(procedures.EnvIntegrityOrder)
	if nsaW == nil {
		nsaW = &nsaWorld{}
	}
	nsaW.cfgOrder, nsaW.cfgErr = procedures.ResolveIntegrityOrder(order)
	return nil
}

func nsaLoadIntegrityConfigEnv(value string) error {
	if err := os.Setenv(procedures.EnvIntegrityOrder, value); err != nil {
		return err
	}
	if nsaW == nil {
		nsaW = &nsaWorld{}
	}
	nsaW.cfgOrder, nsaW.cfgErr = procedures.ResolveIntegrityOrder("")
	return nil
}

func nsaEffectiveIntegrityOrder(list string) error {
	w := nsaW
	if w.cfgErr != nil {
		return fmt.Errorf("configuration load failed: %w", w.cfgErr)
	}
	want, err := procedures.ParseIntegrityOrder(list)
	if err != nil {
		return err
	}
	if !bytes.Equal(w.cfgOrder, want) {
		return fmt.Errorf("effective integrity order %v, want %v", w.cfgOrder, want)
	}
	return nil
}
