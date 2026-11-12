//go:build functional

package main

// nssaa_e2e_test.go - end-to-end style NSSAA test through REAL NAS encoding.
//
// UERANSIM has no NSSAA support, so this test closes the gap in process:
//
//	test UE  --NAS-5GS (NEA2/NIA2, real shared/nas codec)-->  real nasmsg.Handler
//	                                                            + real RegistrationHandler
//	                                                            + real HTTPNSSAAClient
//	         --Nnssaaf_NSSAA (HTTP/2 + mTLS)-->  REAL AUSF process (nf/ausf/cmd/ausf)
//
// What is real: the AMF NAS handler, procedures and NSSAA HTTP client, the AUSF
// binary (built from source and started as a subprocess with generated mTLS
// material), the NAS security (KAMF -> KNASint/KNASenc via shared/crypto/kdf,
// NIA2 MAC, NEA2 ciphering, DL/UL COUNT), the NAS codec on both sides.
// What is faked: the gNB / NGAP / SCTP leg (a Sender that captures the DL NAS
// PDUs), the UDM / am-data (the UE context is seeded with GPSI and subscribed
// NSSAI), the AAA-S (simulated inside the AUSF), time (T3575 via the handler's
// documented test seam Handler.SetTimerSchedulerForTest, T3522 likewise, PENDING-retry interval by back-dating the stored
// timestamp, since the procedure layer reads time.Now()).
//
// Ref: TS 23.502 §4.2.9.2, TS 24.501 §5.4.7, §8.2.31-§8.2.33, §5.5.2.3.1,
// TS 29.526 §5.2.2.2, TS 33.501 §D.3

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	nasmsg "github.com/francurieses/claudia-5gc/nf/amf/internal/nas"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/procedures"
	"github.com/francurieses/claudia-5gc/shared/crypto/eap"
	"github.com/francurieses/claudia-5gc/shared/crypto/kdf"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nea"
	"github.com/francurieses/claudia-5gc/shared/crypto/nas/nia"
	"github.com/francurieses/claudia-5gc/shared/nas"
	"github.com/francurieses/claudia-5gc/shared/sbi"
	"github.com/francurieses/claudia-5gc/shared/sbi/features"
)

// ---- generic helpers ---------------------------------------------------------

// e2eBuf is a goroutine-safe byte sink for subprocess output / AMF logs.
type e2eBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *e2eBuf) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *e2eBuf) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

func e2eTail(s string, n int) string {
	if len(s) > n {
		return "..." + s[len(s)-n:]
	}
	return s
}

// e2eEventually polls cond until it holds or the deadline passes.
func e2eEventually(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", d, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func e2eRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root %s: %v", root, err)
	}
	return root
}

func e2eFreeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// ---- generated mTLS material --------------------------------------------------

type e2ePKI struct{ ca, srvCert, srvKey, cliCert, cliKey string }

func e2eWritePKI(t *testing.T, dir string) e2ePKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nssaa-e2e-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, typ string, der []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	leaf := func(cn string, serial int64, usage x509.ExtKeyUsage) (string, string) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			DNSNames:     []string{"localhost"},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		kder, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return write(cn+".crt", "CERTIFICATE", der), write(cn+".key", "EC PRIVATE KEY", kder)
	}
	var p e2ePKI
	p.ca = write("ca.crt", "CERTIFICATE", caDER)
	p.srvCert, p.srvKey = leaf("ausf", 2, x509.ExtKeyUsageServerAuth)
	p.cliCert, p.cliKey = leaf("amf", 3, x509.ExtKeyUsageClientAuth)
	return p
}

// ---- the real AUSF as a subprocess ---------------------------------------------

func e2eBuildAUSF(t *testing.T, root, outDir string) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("go toolchain not in PATH, cannot build the AUSF: %v", err)
	}
	bin := filepath.Join(outDir, "ausf")
	cmd := exec.Command(goBin, "build", "-o", bin, "./nf/ausf/cmd/ausf")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build the AUSF (real NSSAAF side unavailable): %v\n%s", err, e2eTail(string(out), 2000))
	}
	return bin
}

type e2eAUSF struct {
	t       *testing.T
	root    string
	bin     string
	cfgPath string
	addr    string
	metrics string
	pki     e2ePKI
	out     *e2eBuf

	mu   sync.Mutex
	cmd  *exec.Cmd
	done chan struct{}
}

func newE2EAUSF(t *testing.T, root, bin string) *e2eAUSF {
	t.Helper()
	dir := t.TempDir()
	a := &e2eAUSF{t: t, root: root, bin: bin, out: &e2eBuf{}, pki: e2eWritePKI(t, dir),
		addr: e2eFreeAddr(t), metrics: e2eFreeAddr(t)}
	cfg := fmt.Sprintf(`nf_instance_id: "00000000-0000-4002-8000-0000000000e2"
plmn:
  mcc: "001"
  mnc: "01"
sbi:
  address: %q
  authority: %q
  tls:
    cert_file: %q
    key_file: %q
    ca_file: %q
peers:
  udm: "127.0.0.1:1"
metrics:
  address: %q
`, a.addr, a.addr, a.pki.srvCert, a.pki.srvKey, a.pki.ca, a.metrics)
	a.cfgPath = filepath.Join(dir, "ausf.yaml")
	if err := os.WriteFile(a.cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		a.stop()
		if t.Failed() {
			t.Logf("AUSF output (tail):\n%s", e2eTail(a.out.String(), 6000))
		}
	})
	a.start()
	return a
}

// start launches the AUSF and waits until its SBI port accepts TLS.
func (a *e2eAUSF) start() {
	a.t.Helper()
	cmd := exec.Command(a.bin)
	cmd.Dir = a.root
	cmd.Env = append(os.Environ(), "CONFIG_PATH="+a.cfgPath, "METRICS_ADDRESS="+a.metrics,
		"OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:1", "NF_RELEASE_PROFILE=rel19")
	cmd.Stdout, cmd.Stderr = a.out, a.out
	if err := cmd.Start(); err != nil {
		a.t.Skipf("cannot start the AUSF subprocess: %v", err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	a.mu.Lock()
	a.cmd, a.done = cmd, done
	a.mu.Unlock()
	deadline := time.Now().Add(20 * time.Second)
	for {
		select {
		case <-done:
			a.t.Skipf("AUSF subprocess exited at start-up (real NSSAAF side unavailable):\n%s", e2eTail(a.out.String(), 3000))
		default:
		}
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", a.addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // readiness probe only
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			a.stop()
			a.t.Skipf("AUSF did not listen on %s within 20s:\n%s", a.addr, e2eTail(a.out.String(), 3000))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// stop kills the AUSF (NSSAAF unreachable from now on).
func (a *e2eAUSF) stop() {
	a.mu.Lock()
	cmd, done := a.cmd, a.done
	a.cmd = nil
	a.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	<-done
}

// logLines returns the JSON log lines of the AUSF with the given msg.
func (a *e2eAUSF) logLines(msg string) []map[string]any {
	var out []map[string]any
	for _, ln := range strings.Split(a.out.String(), "\n") {
		if !strings.HasPrefix(ln, "{") {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(ln), &m) == nil && m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

// waitRelay waits for n "NSSAA EAP relayed to AAA-S" lines and returns them.
func (a *e2eAUSF) waitLog(msg string, n int) []map[string]any {
	a.t.Helper()
	var got []map[string]any
	e2eEventually(a.t, fmt.Sprintf("%d AUSF log line(s) %q", n, msg), 5*time.Second, func() bool {
		got = a.logLines(msg)
		return len(got) >= n
	})
	return got
}

// ---- fake gNB: captures every DL NAS PDU ---------------------------------------

type e2eDLItem struct {
	via string // "DL NAS TRANSPORT" or "InitialContextSetupRequest"
	pdu []byte
}

type e2eGNB struct {
	mu       sync.Mutex
	items    []e2eDLItem
	read     int
	releases int
}

func (g *e2eGNB) add(via string, pdu []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.items = append(g.items, e2eDLItem{via, append([]byte(nil), pdu...)})
}

func (g *e2eGNB) SendDownlinkNASTransport(_ *amfctx.UEContext, pdu []byte) error {
	g.add("DL NAS TRANSPORT", pdu)
	return nil
}

func (g *e2eGNB) SendInitialContextSetupRequest(_ *amfctx.UEContext, pdu []byte, _ [32]byte, _, _ byte,
	_, _ uint16, _ []ngap.PDUSessionSetupItemCxtReq) error {
	g.add("InitialContextSetupRequest", pdu)
	return nil
}

func (g *e2eGNB) SendPDUSessionResourceSetupRequest(*amfctx.UEContext, uint8, []byte, []byte) error {
	return nil
}
func (g *e2eGNB) SendPDUSessionResourceReleaseCommand(*amfctx.UEContext, uint8, []byte) error {
	return nil
}
func (g *e2eGNB) SendPDUSessionResourceModifyRequest(*amfctx.UEContext, uint8, []byte, []byte) error {
	return nil
}
func (g *e2eGNB) SendUEContextReleaseCommandForUE(*amfctx.UEContext, int, int64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.releases++
	return nil
}

func (g *e2eGNB) unread() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.items) - g.read
}

func (g *e2eGNB) next() (e2eDLItem, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.read >= len(g.items) {
		return e2eDLItem{}, false
	}
	g.read++
	return g.items[g.read-1], true
}

func (g *e2eGNB) releaseCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.releases
}

// e2eUDM is the (faked) UDM: only the UECM de-registration of the AMF is used.
type e2eUDM struct {
	mu    sync.Mutex
	dereg []string
}

func (u *e2eUDM) RegisterAMF(context.Context, string, string, string) error { return nil }
func (u *e2eUDM) GetAMSubscriptionData(context.Context, string) (*procedures.UDMAMSubscription, error) {
	return &procedures.UDMAMSubscription{}, nil
}
func (u *e2eUDM) DeregisterUECM(_ context.Context, supi string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.dereg = append(u.dereg, supi)
	return nil
}

// ---- fake clock for T3575 / T3522 --------------------------------------------------------

type e2eTimer struct {
	d       time.Duration
	f       func()
	stopped bool
}

func (t *e2eTimer) Stop() bool {
	// guarded by the clock mutex through e2eClock methods; Stop itself is called
	// from the AMF goroutine, so it takes the package-level lock.
	e2eTimerMu.Lock()
	defer e2eTimerMu.Unlock()
	was := !t.stopped
	t.stopped = true
	return was
}

var e2eTimerMu sync.Mutex

type e2eClock struct {
	mu     sync.Mutex
	timers []*e2eTimer
}

func (c *e2eClock) after(d time.Duration, f func()) amfctx.NSSAATimerStopper {
	t := &e2eTimer{d: d}
	t.f = func() {
		e2eTimerMu.Lock()
		t.stopped = true
		e2eTimerMu.Unlock()
		f()
	}
	c.mu.Lock()
	c.timers = append(c.timers, t)
	c.mu.Unlock()
	return t
}

func (c *e2eClock) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}

func (c *e2eClock) last() *e2eTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.timers[len(c.timers)-1]
}

// live reports the running T3575 timers (15 s); liveOf any duration.
func (c *e2eClock) live() int { return c.liveOf(15 * time.Second) }

func (c *e2eClock) liveOf(d time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	e2eTimerMu.Lock()
	defer e2eTimerMu.Unlock()
	n := 0
	for _, t := range c.timers {
		if t.d == d && !t.stopped {
			n++
		}
	}
	return n
}

// ---- the AMF-side environment ---------------------------------------------------

var (
	e2eSliceA = amfctx.SNSSAISubscribed{SST: 1, SD: "000003", SubjectToNSSAA: true}
	e2eSliceB = amfctx.SNSSAISubscribed{SST: 1, SD: "000001"}
	e2eNasA   = nas.SNSSAI{SST: 1, SD: 3}
	e2eNasB   = nas.SNSSAI{SST: 1, SD: 1}
)

type e2eEnv struct {
	t     *testing.T
	h     *nasmsg.Handler
	reg   *procedures.RegistrationHandler
	gnb   *e2eGNB
	udm   *e2eUDM
	clk   *e2eClock
	ue    *amfctx.UEContext
	ausf  *e2eAUSF
	log   *e2eBuf
	ulCnt uint32 // UE-side UL NAS COUNT
	dlCnt uint32 // UE-side expected DL NAS COUNT
	kint  []byte
	kenc  []byte
}

// newE2EEnv wires the real AMF NAS handler exactly like cmd/amf/main.go does for
// NSSAA (HTTPNSSAAClient + WithNSSAA + WithNSSAASpecLiteral) and seeds one UE in
// 5GMM-REGISTERED with an active NIA2/NEA2 security context derived from a KAMF.
func newE2EEnv(t *testing.T, ausf *e2eAUSF, release string, subscribed []amfctx.SNSSAISubscribed) *e2eEnv {
	t.Helper()
	e := &e2eEnv{t: t, ausf: ausf, gnb: &e2eGNB{}, udm: &e2eUDM{}, clk: &e2eClock{}, log: &e2eBuf{}}
	logger := newE2ELogger(e.log)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("AMF log (tail):\n%s", e2eTail(e.log.String(), 6000))
		}
	})

	httpClient, err := sbi.NewMTLSClient(ausf.pki.ca, ausf.pki.cliCert, ausf.pki.cliKey)
	if err != nil {
		t.Fatal(err)
	}
	profile := smsfProfile(t, release)

	mgr := amfctx.NewManager(amfctx.AMFIdentity{MCC: "001", MNC: "01"}, nil, nil, nil)
	e.reg = procedures.NewRegistrationHandler(mgr, nil, e.udm, nil, "e2e-amf", "001", "01", logger)
	e.reg.WithNSSAA(&HTTPNSSAAClient{address: ausf.addr, client: httpClient, profile: profile})
	e.reg.WithNSSAASpecLiteral(features.SpecLiteral(profile))
	e.h = nasmsg.NewHandler(e.gnb, e.reg, logger)
	e.h.SetTimerSchedulerForTest(e.clk.after) // T3575 and T3522 fire only when the test says so

	kamf := bytes.Repeat([]byte{0xA5}, 32)
	e.kint, e.kenc = kdf.KNASint(kamf, 2), kdf.KNASenc(kamf, 2)
	ue := mgr.AllocateUEContext(1)
	mgr.SetSUPI(ue, "imsi-001010000000001")
	ue.RANUENGAPId = 1
	ue.GPSI = "msisdn-12025550100" // as read from Nudm_SDM am-data "gpsis"
	ue.CMState = amfctx.CMConnected
	ue.State = amfctx.GMMRegistered
	ue.SecurityCtx = amfctx.SecurityContext{
		Active: true, IntegrityAlgID: 2, CipheringAlgID: 2,
		KAMF: kamf, KNASint: e.kint, KNASenc: e.kenc,
	}
	ue.SubscribedNSSAI = subscribed
	ue.AllowedNSSAI = append([]amfctx.SNSSAISubscribed(nil), subscribed...)
	e.ue = ue
	// Registration step "slices withheld for NSSAA" (the real function).
	e.run(func() { e.reg.SplitPendingNSSAA(ue) })
	return e
}

func newE2ELogger(w *e2eBuf) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, nil))
}

// run executes f on the UE's serial queue (like the NGAP layer does for every
// NAS PDU) and waits for it; it doubles as a barrier for already queued work.
func (e *e2eEnv) run(f func()) {
	done := make(chan struct{})
	e.ue.EnqueueSerial(func() { defer close(done); f() })
	<-done
}

// ---- UE side: secured UL, deciphered DL --------------------------------------------

// ulPDU builds a NAS-protected UL PDU for message type mt (TS 24.501 §4.4.5,
// TS 33.501 §D.3.3): SHT 2 = integrity protected and ciphered (NEA2 over the
// plain inner message, NIA2 MAC over SN||ciphertext); SHT 1 = integrity only.
func (e *e2eEnv) ulPDU(sht nas.SecurityHeaderType, mt nas.MessageType, body []byte) []byte {
	e.t.Helper()
	inner := append([]byte{nas.PDMobilityManagement, byte(nas.SecurityHeaderPlainNAS), byte(mt)}, body...)
	count := e.ulCnt
	e.ulCnt++
	payload := inner
	if sht == nas.SecurityHeaderIntegrityProtectedAndCiphered {
		c, err := nea.NEA2(e.kenc, count, 0x01, 0x00, inner)
		if err != nil {
			e.t.Fatal(err)
		}
		payload = c
	}
	sqn := byte(count & 0xFF)
	mac, err := nia.NIA2(e.kint, count, 0x01, 0x00, append([]byte{sqn}, payload...))
	if err != nil {
		e.t.Fatal(err)
	}
	pdu := []byte{nas.PDMobilityManagement, byte(sht)}
	pdu = append(pdu, mac...)
	pdu = append(pdu, sqn)
	return append(pdu, payload...)
}

// ul delivers a UL NAS PDU to the AMF handler on the UE's serial queue and
// returns the handler's error.
func (e *e2eEnv) ul(sht nas.SecurityHeaderType, mt nas.MessageType, body []byte) error {
	e.t.Helper()
	pdu := e.ulPDU(sht, mt, body)
	var err error
	e.run(func() { err = e.h.HandleNASMessage(context.Background(), e.ue, pdu) })
	return err
}

func (e *e2eEnv) mustUL(mt nas.MessageType, body []byte) {
	e.t.Helper()
	if err := e.ul(nas.SecurityHeaderIntegrityProtectedAndCiphered, mt, body); err != nil {
		e.t.Fatalf("AMF rejected UL %#x: %v", byte(mt), err)
	}
}

// e2eDL is one decoded DL NAS message as the UE sees it.
type e2eDL struct {
	via string
	mt  nas.MessageType
	msg *nas.Message
}

// recv takes the next captured DL PDU and, as a UE does, checks the security
// header (SHT 2), the SN, the NIA2 MAC (DL, bearer 1) and deciphers with NEA2
// before decoding the plain 5GMM message with shared/nas.
func (e *e2eEnv) recv() e2eDL {
	e.t.Helper()
	e2eEventually(e.t, "a DL NAS PDU", 5*time.Second, func() bool { return e.gnb.unread() > 0 })
	it, _ := e.gnb.next()
	p := it.pdu
	if len(p) < 10 || p[0] != nas.PDMobilityManagement || nas.SecurityHeaderType(p[1]&0x0F) != nas.SecurityHeaderIntegrityProtectedAndCiphered {
		e.t.Fatalf("DL PDU is not SHT 2 protected 5GMM: % x", p[:min(len(p), 8)])
	}
	count := e.dlCnt
	e.dlCnt++
	if p[6] != byte(count&0xFF) {
		e.t.Fatalf("DL SN = %d, want %d (NAS COUNT %d)", p[6], count&0xFF, count)
	}
	ok, err := nia.Verify(e.kint, count, 0x01, 0x01, append([]byte{p[6]}, p[7:]...), p[2:6])
	if err != nil || !ok {
		e.t.Fatalf("DL NIA2 MAC invalid (count %d): ok=%v err=%v", count, ok, err)
	}
	inner, err := nea.NEA2(e.kenc, count, 0x01, 0x01, p[7:])
	if err != nil {
		e.t.Fatal(err)
	}
	if len(inner) < 3 || inner[0] != nas.PDMobilityManagement || inner[1] != byte(nas.SecurityHeaderPlainNAS) {
		e.t.Fatalf("deciphered inner message is not plain 5GMM: % x", inner[:min(len(inner), 8)])
	}
	msg, err := nas.Decode(inner)
	if err != nil {
		e.t.Fatalf("decode DL %#x: %v", inner[2], err)
	}
	return e2eDL{via: it.via, mt: msg.Header.MessageType, msg: msg}
}

func (e *e2eEnv) recvCommand() *nas.NSSAAuthCommand {
	e.t.Helper()
	d := e.recv()
	if d.mt != nas.MsgTypeNetworkSliceSpecificAuthCommand {
		e.t.Fatalf("got DL %#x, want NETWORK SLICE-SPECIFIC AUTHENTICATION COMMAND (0x50)", byte(d.mt))
	}
	return d.msg.Body.(*nas.NSSAAuthCommand)
}

func (e *e2eEnv) recvResult() *nas.NSSAAuthResult {
	e.t.Helper()
	d := e.recv()
	if d.mt != nas.MsgTypeNetworkSliceSpecificAuthResult {
		e.t.Fatalf("got DL %#x, want NETWORK SLICE-SPECIFIC AUTHENTICATION RESULT (0x52)", byte(d.mt))
	}
	return d.msg.Body.(*nas.NSSAAuthResult)
}

func (e *e2eEnv) recvCUC() *nas.ConfigurationUpdateCommand {
	e.t.Helper()
	d := e.recv()
	if d.mt != nas.MsgTypeConfigurationUpdateCommand {
		e.t.Fatalf("got DL %#x, want CONFIGURATION UPDATE COMMAND (0x54)", byte(d.mt))
	}
	return d.msg.Body.(*nas.ConfigurationUpdateCommand)
}

func (e *e2eEnv) recvDereg() *nas.DeregistrationRequestNW {
	e.t.Helper()
	d := e.recv()
	if d.mt != nas.MsgTypeDeregistrationRequestNW {
		e.t.Fatalf("got DL %#x, want DEREGISTRATION REQUEST (UE terminated)", byte(d.mt))
	}
	return e.decodeDereg(d)
}

// decodeDereg decodes the DEREGISTRATION REQUEST body (shared/nas Decode leaves
// it as RawBody, so the dedicated decoder is used).
func (e *e2eEnv) decodeDereg(d e2eDL) *nas.DeregistrationRequestNW {
	e.t.Helper()
	raw, ok := d.msg.Body.(*nas.RawBody)
	if !ok {
		e.t.Fatalf("DEREGISTRATION REQUEST body is %T", d.msg.Body)
	}
	req, err := nas.DecodeDeregistrationRequestNW(raw.Data)
	if err != nil {
		e.t.Fatal(err)
	}
	return req
}

// silent asserts the AMF sent nothing more to the UE (after draining the UE's
// serial queue, so nothing is still in flight).
func (e *e2eEnv) silent(what string) {
	e.t.Helper()
	e.run(func() {})
	if n := e.gnb.unread(); n > 0 {
		var types []string
		for i := 0; i < n; i++ {
			types = append(types, fmt.Sprintf("%#x", byte(e.recv().mt)))
		}
		e.t.Fatalf("%s: AMF sent %d unexpected DL NAS message(s): %v", what, n, types)
	}
}

// completeWith answers the last COMMAND with an EAP-Response and the S-NSSAI.
func (e *e2eEnv) complete(sn nas.SNSSAI, eapResp []byte) {
	e.t.Helper()
	body, err := nas.EncodeNSSAAuthComplete(&nas.NSSAAuthComplete{SNSSAI: sn, EAPMessage: eapResp})
	if err != nil {
		e.t.Fatal(err)
	}
	e.mustUL(nas.MsgTypeNetworkSliceSpecificAuthComplete, body)
}

// registrationComplete answers the REGISTRATION ACCEPT. The env synthesises a
// registered UE without running the Accept leg, so when none is pending the
// helper marks one as awaiting its COMPLETE (the AMF ignores an unsolicited
// REGISTRATION COMPLETE, TS 24.501 §5.5.1.2.4).
func (e *e2eEnv) registrationComplete() {
	e.run(func() {
		if e.ue.RegStage() == amfctx.RegStageNone {
			e.ue.SetRegStage(amfctx.RegStageAcceptSent)
		}
	})
	e.mustUL(nas.MsgTypeRegistrationComplete, nil)
}

// serviceRequest sends a Service Request (SHT 1, integrity protected, TS 24.501
// §4.4.5) for a CM-IDLE UE: service type "signalling", ngKSI 0, 5G-S-TMSI.
func (e *e2eEnv) serviceRequest() {
	e.t.Helper()
	e.run(func() { e.ue.CMState = amfctx.CMIdle })
	body := []byte{
		byte(nas.ServiceTypeSignalling<<4) | 0x00, // service type | NAS key set identifier
		0x00, 0x07, 0xF4, 0x00, 0x41, 0xDE, 0xAD, 0xBE, 0xEF, // 5G-S-TMSI LV-E
	}
	if err := e.ul(nas.SecurityHeaderIntegrityProtected, nas.MsgTypeServiceRequest, body); err != nil {
		e.t.Fatalf("AMF rejected Service Request: %v", err)
	}
}

// setER marks the UE as supporting extended rejected NSSAI (ER-NSSAI bit of the
// 5GMM capability IE of its REGISTRATION REQUEST, TS 24.501 §9.11.3.1).
func (e *e2eEnv) setER(on bool) { e.uePeek(func(ue *amfctx.UEContext) { ue.ERNSSAISupported = on }) }

// periodicUpdate sends a periodic REGISTRATION REQUEST (security context active,
// TS 23.502 §4.2.2.2.4), with or without the ER-NSSAI bit in the 5GMM capability
// IE (octet 5 bit 5), and returns the REGISTRATION ACCEPT of the answer.
func (e *e2eEnv) periodicUpdate(er bool) *nas.RegistrationAccept {
	e.t.Helper()
	guti := []byte{0xF2, 0x00, 0xF1, 0x10, 0x02, 0x00, 0x41, 0xDE, 0xAD, 0xBE, 0xEF}
	body := []byte{byte(nas.RegistrationTypePeriodic), 0x00, byte(len(guti))}
	body = append(body, guti...)
	if er {
		body = append(body, 0x10, 0x03, 0x00, 0x00, 0x10) // 5GMM capability, ER-NSSAI = octet 5 bit 5
	}
	e.mustUL(nas.MsgTypeRegistrationRequest, body)
	d := e.recv()
	if d.mt != nas.MsgTypeRegistrationAccept || d.via != "InitialContextSetupRequest" {
		e.t.Fatalf("got %#x via %s, want REGISTRATION ACCEPT in the InitialContextSetupRequest", byte(d.mt), d.via)
	}
	return d.msg.Body.(*nas.RegistrationAccept)
}

// wantExtendedRejected asserts the Extended rejected NSSAI IE carries exactly
// sn with cause 2 (NSSAA failed or revoked) and no mapped S-NSSAI.
func (e *e2eEnv) wantExtendedRejected(x *nas.ExtendedRejectedNSSAI, sn nas.SNSSAI) {
	e.t.Helper()
	if x == nil || len(x.Lists) != 1 || len(x.Lists[0].Elements) != 1 {
		e.t.Fatalf("Extended rejected NSSAI = %+v, want one list with one S-NSSAI", x)
	}
	el := x.Lists[0].Elements[0]
	if el.Cause != nas.RejectedCauseNSSAAFailedOrRevoked || el.SNSSAI != sn {
		e.t.Fatalf("Extended rejected NSSAI element = %+v, want cause 2 and %+v", el, sn)
	}
}

// failSliceA runs NSSAA for slice A up to the AAA-S rejection and consumes the RESULT.
func (e *e2eEnv) failSliceA(nai string) {
	e.t.Helper()
	e.registrationComplete()
	cmd := e.recvCommand()
	e.wantIdentityCommand(cmd, e2eNasA)
	e.complete(e2eNasA, e2eIdentity(e, cmd, nai))
	id, _ := eap.Identifier(cmd.EAPMessage)
	e.wantEAPResult(e.recvResult(), e2eNasA, eap.CodeFailure, id)
}

// ---- assertion helpers -----------------------------------------------------------------

func e2eIdentity(e *e2eEnv, cmd *nas.NSSAAuthCommand, nai string) []byte {
	e.t.Helper()
	id, err := eap.Identifier(cmd.EAPMessage)
	if err != nil {
		e.t.Fatal(err)
	}
	return eap.BuildIdentityResponse(id, nai)
}

// wantIdentityCommand asserts a COMMAND for slice carrying EAP-Request/Identity
// (TS 24.501 §8.2.31, RFC 3748 §5.1) and that T3575 is running for it.
func (e *e2eEnv) wantIdentityCommand(cmd *nas.NSSAAuthCommand, sn nas.SNSSAI) {
	e.t.Helper()
	if cmd.SNSSAI != sn {
		e.t.Fatalf("COMMAND S-NSSAI = %+v, want %+v", cmd.SNSSAI, sn)
	}
	if err := eap.Validate(cmd.EAPMessage); err != nil {
		e.t.Fatalf("COMMAND EAP message invalid: %v", err)
	}
	code, _ := eap.Code(cmd.EAPMessage)
	typ, _ := eap.Type(cmd.EAPMessage)
	if code != eap.CodeRequest || typ != eap.TypeIdentity {
		e.t.Fatalf("COMMAND EAP = % x, want EAP-Request/Identity", cmd.EAPMessage)
	}
}

func (e *e2eEnv) wantEAPResult(r *nas.NSSAAuthResult, sn nas.SNSSAI, code byte, id byte) {
	e.t.Helper()
	if r.SNSSAI != sn {
		e.t.Fatalf("RESULT S-NSSAI = %+v, want %+v", r.SNSSAI, sn)
	}
	want := []byte{code, id, 0, 4}
	if !bytes.Equal(r.EAPMessage, want) {
		e.t.Fatalf("RESULT EAP message = % x, want % x", r.EAPMessage, want)
	}
}

func e2eHasSNSSAI(l []nas.SNSSAI, s nas.SNSSAI) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// wantCUC asserts the CONFIGURATION UPDATE COMMAND: acknowledgement requested
// (Configuration update indication ACK bit), Allowed NSSAI and Rejected NSSAI.
func (e *e2eEnv) wantCUC(c *nas.ConfigurationUpdateCommand, allowed, notAllowed []nas.SNSSAI, rejected []nas.RejectedSNSSAI) {
	e.t.Helper()
	if c.ConfigUpdateIndication == nil || *c.ConfigUpdateIndication&0x01 == 0 {
		e.t.Fatalf("CUC Configuration update indication = %v, want ACK bit set", c.ConfigUpdateIndication)
	}
	var got []nas.SNSSAI
	if c.AllowedNSSAI != nil {
		got = c.AllowedNSSAI.SNSSAIs
	}
	for _, s := range allowed {
		if !e2eHasSNSSAI(got, s) {
			e.t.Fatalf("CUC Allowed NSSAI %+v lacks %+v", got, s)
		}
	}
	for _, s := range notAllowed {
		if e2eHasSNSSAI(got, s) {
			e.t.Fatalf("CUC Allowed NSSAI %+v must not contain %+v", got, s)
		}
	}
	if len(c.RejectedNSSAI) != len(rejected) {
		e.t.Fatalf("CUC Rejected NSSAI = %+v, want %+v", c.RejectedNSSAI, rejected)
	}
	for i := range rejected {
		if c.RejectedNSSAI[i] != rejected[i] {
			e.t.Fatalf("CUC Rejected NSSAI = %+v, want %+v", c.RejectedNSSAI, rejected)
		}
	}
}

var e2eRejectedA = []nas.RejectedSNSSAI{{Cause: nas.RejectedCauseNSSAAFailedOrRevoked, SNSSAI: e2eNasA}}

// uePeek reads UE-context state on the serial queue (race-free).
func (e *e2eEnv) uePeek(f func(ue *amfctx.UEContext)) { e.run(func() { f(e.ue) }) }

func e2eSubHas(l []amfctx.SNSSAISubscribed, s amfctx.SNSSAISubscribed) bool {
	for _, x := range l {
		if x.SST == s.SST && x.SD == s.SD {
			return true
		}
	}
	return false
}

// finish asserts the UE-side and AMF-side NAS COUNTs never diverged.
func (e *e2eEnv) finish() {
	e.t.Helper()
	e.silent("end of scenario")
	e.uePeek(func(ue *amfctx.UEContext) {
		if ue.SecurityCtx.UplinkCount != e.ulCnt || ue.SecurityCtx.DownlinkCount != e.dlCnt {
			e.t.Errorf("NAS COUNT diverged: AMF UL/DL = %d/%d, UE UL/DL = %d/%d",
				ue.SecurityCtx.UplinkCount, ue.SecurityCtx.DownlinkCount, e.ulCnt, e.dlCnt)
		}
	})
}

// ---- the scenarios ----------------------------------------------------------------------

// TestNSSAAE2E drives NSSAA through real NAS bytes, the real AMF NAS/procedure
// layer + HTTPNSSAAClient and the real AUSF (Nnssaaf_NSSAA) process.
// Ref: TS 23.502 §4.2.9.2, TS 24.501 §5.4.7, TS 29.526 §5.2.2
func TestNSSAAE2E(t *testing.T) {
	root := e2eRepoRoot(t)
	bin := e2eBuildAUSF(t, root, t.TempDir())
	both := []amfctx.SNSSAISubscribed{e2eSliceA, e2eSliceB}
	onlyA := []amfctx.SNSSAISubscribed{e2eSliceA}

	// (1) success: COMMAND(EAP-Request/Identity) -> COMPLETE(identity) -> RESULT(EAP-Success) -> CUC(Allowed NSSAI).
	t.Run("rel19 success: COMMAND, COMPLETE, RESULT EAP-Success, CUC with Allowed NSSAI", func(t *testing.T) {
		e := newE2EEnv(t, newE2EAUSF(t, root, bin), "rel19", both)
		e.uePeek(func(ue *amfctx.UEContext) {
			if e2eSubHas(ue.AllowedNSSAI, e2eSliceA) || len(ue.PendingNSSAA) != 1 {
				t.Errorf("slice must be withheld before NSSAA: allowed=%+v pending=%+v", ue.AllowedNSSAI, ue.PendingNSSAA)
			}
		})
		e.registrationComplete()
		cmd := e.recvCommand()
		e.wantIdentityCommand(cmd, e2eNasA)
		if e.clk.live() != 1 || e.clk.last().d != 15*time.Second {
			t.Fatalf("T3575 not running with 15 s after the COMMAND: live=%d", e.clk.live())
		}
		e.complete(e2eNasA, e2eIdentity(e, cmd, "alice@nssaa"))
		id, _ := eap.Identifier(cmd.EAPMessage)
		e.wantEAPResult(e.recvResult(), e2eNasA, eap.CodeSuccess, id)
		if e.clk.live() != 0 {
			t.Fatalf("T3575 still running after COMPLETE: live=%d", e.clk.live())
		}
		e.wantCUC(e.recvCUC(), []nas.SNSSAI{e2eNasA, e2eNasB}, nil, nil)
		e.mustUL(nas.MsgTypeConfigurationUpdateComplete, nil)
		e.uePeek(func(ue *amfctx.UEContext) {
			if !e2eSubHas(ue.AllowedNSSAI, e2eSliceA) {
				t.Errorf("AMF context lacks the authorized slice: %+v", ue.AllowedNSSAI)
			}
		})
		// The relay really went to the TS 29.526 resource of the real AUSF.
		for _, l := range e.ausf.waitLog("NSSAA EAP relayed to AAA-S", 1) {
			if l["interface"] != "Nnssaaf" || l["result"] != "EAP_SUCCESS" {
				t.Errorf("AUSF relay log = %v", l)
			}
		}
		e.finish()
	})

	// (2) reject: AAA-S rejects -> RESULT(EAP-Failure) -> CUC with Rejected NSSAI cause 2 (another slice allowed).
	t.Run("rel19 reject: RESULT EAP-Failure then CUC with Rejected NSSAI cause 2", func(t *testing.T) {
		e := newE2EEnv(t, newE2EAUSF(t, root, bin), "rel19", both)
		e.registrationComplete()
		cmd := e.recvCommand()
		e.wantIdentityCommand(cmd, e2eNasA)
		e.complete(e2eNasA, e2eIdentity(e, cmd, "bob-reject@nssaa"))
		id, _ := eap.Identifier(cmd.EAPMessage)
		e.wantEAPResult(e.recvResult(), e2eNasA, eap.CodeFailure, id)
		e.wantCUC(e.recvCUC(), []nas.SNSSAI{e2eNasB}, []nas.SNSSAI{e2eNasA}, e2eRejectedA)
		e.uePeek(func(ue *amfctx.UEContext) {
			if e2eSubHas(ue.AllowedNSSAI, e2eSliceA) || !e2eSubHas(ue.RejectedNSSAI, e2eSliceA) {
				t.Errorf("allowed=%+v rejected=%+v", ue.AllowedNSSAI, ue.RejectedNSSAI)
			}
		})
		e.waitAUSFReject()
		e.finish()
	})

	// (3) multi-round: identity "challenge" -> 2nd COMMAND carries the AAA EAP-Request -> COMPLETE -> RESULT.
	t.Run("rel19 multi-round: second COMMAND carries the AAA-S EAP-Request", func(t *testing.T) {
		e := newE2EEnv(t, newE2EAUSF(t, root, bin), "rel19", both)
		e.registrationComplete()
		cmd := e.recvCommand()
		e.wantIdentityCommand(cmd, e2eNasA)
		e.complete(e2eNasA, e2eIdentity(e, cmd, "carol-challenge@nssaa"))

		cmd2 := e.recvCommand()
		if cmd2.SNSSAI != e2eNasA {
			t.Fatalf("2nd COMMAND S-NSSAI = %+v", cmd2.SNSSAI)
		}
		id1, _ := eap.Identifier(cmd.EAPMessage)
		wantReq := []byte{eap.CodeRequest, id1 + 1, 0, 6, 4, 1} // simulated AAA-S MD5-Challenge, RFC 3748 §5.4
		if !bytes.Equal(cmd2.EAPMessage, wantReq) {
			t.Fatalf("2nd COMMAND EAP = % x, want % x (AAA-S EAP-Request)", cmd2.EAPMessage, wantReq)
		}
		if e.clk.live() != 1 || e.clk.count() != 2 {
			t.Fatalf("T3575 must be restarted for the 2nd COMMAND: live=%d total=%d", e.clk.live(), e.clk.count())
		}
		e.silent("between the rounds (no RESULT/CUC yet)")
		e.complete(e2eNasA, []byte{eap.CodeResponse, id1 + 1, 0, 6, 4, 1})
		e.wantEAPResult(e.recvResult(), e2eNasA, eap.CodeSuccess, id1+1)
		e.wantCUC(e.recvCUC(), []nas.SNSSAI{e2eNasA, e2eNasB}, nil, nil)
		if e.clk.live() != 0 {
			t.Fatalf("T3575 still running after the final COMPLETE")
		}
		lines := e.ausf.waitLog("NSSAA confirmation processed", 1)
		if lines[0]["result"] != "EAP_SUCCESS" || lines[0]["interface"] != "Nnssaaf" {
			t.Errorf("AUSF PUT log = %v", lines[0])
		}
		e.finish()
	})

	// (4) T3575: the UE never answers -> 4 retransmissions, 5th expiry fails the slice.
	t3575 := func(t *testing.T, subs []amfctx.SNSSAISubscribed, wantDereg bool) {
		e := newE2EEnv(t, newE2EAUSF(t, root, bin), "rel19", subs)
		e.registrationComplete()
		first := e.recvCommand()
		e.wantIdentityCommand(first, e2eNasA)
		for i := 1; i <= 4; i++ {
			if e.clk.live() != 1 || e.clk.last().d != 15*time.Second {
				t.Fatalf("before expiry %d: live T3575=%d", i, e.clk.live())
			}
			tm := e.clk.last()
			tm.f()
			e.run(func() {})
			re := e.recvCommand()
			if re.SNSSAI != first.SNSSAI || !bytes.Equal(re.EAPMessage, first.EAPMessage) {
				t.Fatalf("retransmission %d differs from the first COMMAND: %+v vs %+v", i, re, first)
			}
		}
		e.silent("after 4 retransmissions")
		e.clk.last().f() // fifth expiry
		e.run(func() {})
		if e.clk.live() != 0 {
			t.Fatalf("T3575 still running after the 5th expiry")
		}
		if wantDereg {
			d := e.recvDereg()
			if d.Cause5GMM != 62 || d.AccessType != 1 || d.ReregistrationRequired ||
				len(d.RejectedNSSAI) != 1 || d.RejectedNSSAI[0] != e2eRejectedA[0] {
				t.Fatalf("DEREGISTRATION REQUEST = %+v, want cause 62, 3GPP access, no re-registration, Rejected NSSAI %+v", d, e2eRejectedA)
			}
		} else {
			e.wantCUC(e.recvCUC(), []nas.SNSSAI{e2eNasB}, []nas.SNSSAI{e2eNasA}, e2eRejectedA)
		}
		e.uePeek(func(ue *amfctx.UEContext) {
			if !e2eSubHas(ue.RejectedNSSAI, e2eSliceA) || len(ue.NSSAAPendingStatus) != 0 {
				t.Errorf("slice must be rejected, not PENDING: rejected=%+v pending=%+v", ue.RejectedNSSAI, ue.NSSAAPendingStatus)
			}
		})
		// no RESULT was ever sent (TS 24.501 §5.4.7.2.3 a)): silent() would have named it.
		e.silent("after T3575 abort")
		if n := e.ausf.logLines("NSSAA EAP relayed to AAA-S"); len(n) != 0 {
			t.Errorf("AUSF saw %d relays although the UE never answered", len(n))
		}
		e.finish()
	}
	t.Run("rel19 T3575: 4 retransmissions then slice failed, CUC with Rejected NSSAI", func(t *testing.T) {
		t3575(t, both, false)
	})
	t.Run("rel19 T3575: 4 retransmissions then slice failed, no default left -> DEREGISTRATION REQUEST", func(t *testing.T) {
		t3575(t, onlyA, true)
	})

	// (5) PENDING + retry: NSSAAF down -> no RESULT, PENDING -> back -> Service Request after the min interval -> re-run.
	t.Run("rel19 PENDING: NSSAAF down keeps slice PENDING, Service Request after 60 s re-runs NSSAA", func(t *testing.T) {
		ausf := newE2EAUSF(t, root, bin)
		e := newE2EEnv(t, ausf, "rel19", both)
		e.registrationComplete()
		cmd := e.recvCommand()
		e.wantIdentityCommand(cmd, e2eNasA)
		ausf.stop() // Nnssaaf unreachable
		e.complete(e2eNasA, e2eIdentity(e, cmd, "dave@nssaa"))
		e.silent("NSSAAF down: no RESULT, no CUC, no de-registration")
		if e.clk.live() != 0 {
			t.Fatalf("T3575 must not run for a COMPLETE that was accepted: live=%d", e.clk.live())
		}
		e.uePeek(func(ue *amfctx.UEContext) {
			if !e2eSubHas(ue.NSSAAPendingStatus, e2eSliceA) || e2eSubHas(ue.AllowedNSSAI, e2eSliceA) || e2eSubHas(ue.RejectedNSSAI, e2eSliceA) {
				t.Errorf("slice must be PENDING only: pending=%+v allowed=%+v rejected=%+v",
					ue.NSSAAPendingStatus, ue.AllowedNSSAI, ue.RejectedNSSAI)
			}
		})

		ausf.start() // NSSAAF back
		e.serviceRequest()
		if d := e.recv(); d.mt != nas.MsgTypeServiceAccept || d.via != "InitialContextSetupRequest" {
			t.Fatalf("got %#x via %s, want SERVICE ACCEPT in the InitialContextSetupRequest", byte(d.mt), d.via)
		}
		e.silent("Service Request inside the 60 s minimum interval: no NSSAA re-run")

		// Advance the clock: the procedure layer reads time.Now(), so the stored
		// PENDING timestamp is moved 61 s into the past.
		e.uePeek(func(ue *amfctx.UEContext) {
			for k, at := range ue.NSSAAPendingAt {
				ue.NSSAAPendingAt[k] = at.Add(-(procedures.NSSAAPendingRetryMinInterval + time.Second))
			}
		})
		e.serviceRequest()
		if d := e.recv(); d.mt != nas.MsgTypeServiceAccept {
			t.Fatalf("got %#x, want SERVICE ACCEPT", byte(d.mt))
		}
		cmd = e.recvCommand()
		e.wantIdentityCommand(cmd, e2eNasA)
		e.complete(e2eNasA, e2eIdentity(e, cmd, "dave@nssaa"))
		id, _ := eap.Identifier(cmd.EAPMessage)
		e.wantEAPResult(e.recvResult(), e2eNasA, eap.CodeSuccess, id)
		e.wantCUC(e.recvCUC(), []nas.SNSSAI{e2eNasA, e2eNasB}, nil, nil)
		e.uePeek(func(ue *amfctx.UEContext) {
			if !e2eSubHas(ue.AllowedNSSAI, e2eSliceA) || len(ue.NSSAAPendingStatus) != 0 {
				t.Errorf("after the retry: allowed=%+v pending=%+v", ue.AllowedNSSAI, ue.NSSAAPendingStatus)
			}
		})
		e.finish()
	})

	// (6) every slice failed and no plain default -> DEREGISTRATION REQUEST (UE terminated), cause #62, Rejected NSSAI 0x6D.
	t.Run("rel19 all slices failed, no plain default: DEREGISTRATION REQUEST cause 62 with Rejected NSSAI", func(t *testing.T) {
		e := newE2EEnv(t, newE2EAUSF(t, root, bin), "rel19", onlyA)
		e.registrationComplete()
		cmd := e.recvCommand()
		e.complete(e2eNasA, e2eIdentity(e, cmd, "mallory-reject@nssaa"))
		id, _ := eap.Identifier(cmd.EAPMessage)
		e.wantEAPResult(e.recvResult(), e2eNasA, eap.CodeFailure, id)

		// Look at the raw bytes of the DEREGISTRATION REQUEST.
		d := e.recv()
		if d.mt != nas.MsgTypeDeregistrationRequestNW {
			t.Fatalf("got %#x, want DEREGISTRATION REQUEST (UE terminated), no CUC", byte(d.mt))
		}
		req := e.decodeDereg(d)
		if req.Cause5GMM != 62 || req.AccessType != 1 || req.ReregistrationRequired ||
			len(req.RejectedNSSAI) != 1 || req.RejectedNSSAI[0] != e2eRejectedA[0] {
			t.Fatalf("DEREGISTRATION REQUEST = %+v", req)
		}
		raw, err := nas.EncodeDeregistrationRequestNW(req)
		if err != nil {
			t.Fatal(err)
		}
		// 5GMM cause IEI 0x58 = 62 (0x3E); Rejected NSSAI IEI 0x6D, one entry:
		// length 4 = [cause 2 << 4 | length 2, SST 1, SD 00 00 03] (TS 24.501 §9.11.3.46).
		if !bytes.Contains(raw, []byte{0x58, 0x3E}) || !bytes.Contains(raw, []byte{0x6D, 0x05, 0x42, 0x01, 0x00, 0x00, 0x03}) {
			t.Errorf("DEREGISTRATION REQUEST body % x lacks cause 62 / Rejected NSSAI 0x6D", raw)
		}
		e.uePeek(func(ue *amfctx.UEContext) {
			if ue.State != amfctx.GMMDeregisteredInitiated {
				t.Errorf("UE state = %v, want DEREGISTERED-INITIATED", ue.State)
			}
		})
		// The UE answers with DEREGISTRATION ACCEPT: AMF releases the N2 context.
		e.mustUL(nas.MsgTypeDeregistrationAcceptNW, nil)
		e.silent("after the de-registration")
		e.udm.mu.Lock()
		if len(e.udm.dereg) != 1 || e.udm.dereg[0] != "imsi-001010000000001" {
			t.Errorf("UDM UECM de-registrations = %v", e.udm.dereg)
		}
		e.udm.mu.Unlock()
		if e.gnb.releaseCount() != 1 {
			t.Errorf("UE Context Release Command count = %d, want 1", e.gnb.releaseCount())
		}
		e.uePeek(func(ue *amfctx.UEContext) {
			if ue.State != amfctx.GMMDeregistered {
				t.Errorf("UE state = %v, want DEREGISTERED", ue.State)
			}
		})
		e.finish()
	})

	// (8) ER-NSSAI capable UE (TS 24.501 §5.5.2.3.1, §5.4.4.2, §5.5.1.2.4): the
	// rejected NSSAI goes in the Extended rejected NSSAI IE (0x68) INSTEAD of the
	// Rejected NSSAI IE, in the DEREGISTRATION REQUEST, the CUC and the REGISTRATION ACCEPT.
	t.Run("rel19 ER-NSSAI UE: DEREGISTRATION REQUEST carries the Extended rejected NSSAI IE 0x68, T3522 6 s", func(t *testing.T) {
		e := newE2EEnv(t, newE2EAUSF(t, root, bin), "rel19", onlyA)
		e.setER(true)
		e.failSliceA("ernssai-dereg-reject@nssaa")
		d := e.recv()
		if d.mt != nas.MsgTypeDeregistrationRequestNW {
			t.Fatalf("got %#x, want DEREGISTRATION REQUEST", byte(d.mt))
		}
		req := e.decodeDereg(d)
		if req.Cause5GMM != 62 || req.AccessType != 1 || req.ReregistrationRequired || len(req.RejectedNSSAI) != 0 {
			t.Fatalf("DEREGISTRATION REQUEST = %+v", req)
		}
		e.wantExtendedRejected(req.ExtendedRejectedNSSAI, e2eNasA)
		// On-wire body: octet 4 (spare 0, re-registration not required, 3GPP), 5GMM
		// cause 0x58 0x3E (#62), then the Extended rejected NSSAI IEI 0x68 (TLV, codec
		// owned and byte-tested in shared/nas, TS 24.501 §9.11.3.75).
		raw := d.msg.Body.(*nas.RawBody).Data
		if len(raw) < 4 || raw[0] != 0x01 || raw[1] != 0x58 || raw[2] != 0x3E || raw[3] != 0x68 {
			t.Fatalf("DEREGISTRATION REQUEST body % x, want 01 58 3E 68 ...", raw)
		}
		if e.clk.liveOf(6*time.Second) != 1 {
			t.Fatalf("T3522 (6 s) not running after the DEREGISTRATION REQUEST: %d", e.clk.liveOf(6*time.Second))
		}
		e.mustUL(nas.MsgTypeDeregistrationAcceptNW, nil)
		if e.clk.liveOf(6*time.Second) != 0 {
			t.Fatal("T3522 must stop on DEREGISTRATION ACCEPT")
		}
		e.finish()
	})

	t.Run("rel19 ER-NSSAI UE: CUC carries the Extended rejected NSSAI IE, REGISTRATION ACCEPT too", func(t *testing.T) {
		e := newE2EEnv(t, newE2EAUSF(t, root, bin), "rel19", both)
		e.setER(true)
		e.failSliceA("ernssai-cuc-reject@nssaa")
		cuc := e.recvCUC()
		if len(cuc.RejectedNSSAI) != 0 {
			t.Fatalf("CUC carries the Rejected NSSAI IE too: %+v", cuc.RejectedNSSAI)
		}
		e.wantExtendedRejected(cuc.ExtendedRejectedNSSAI, e2eNasA)
		if cuc.AllowedNSSAI == nil || !e2eHasSNSSAI(cuc.AllowedNSSAI.SNSSAIs, e2eNasB) {
			t.Fatalf("CUC Allowed NSSAI = %+v", cuc.AllowedNSSAI)
		}
		e.mustUL(nas.MsgTypeConfigurationUpdateComplete, nil)
		// periodic registration update with the ER-NSSAI bit: the capability is read
		// from the request and the ACCEPT uses the extended IE.
		e.setER(false)
		ra := e.periodicUpdate(true)
		if len(ra.RejectedNSSAI) != 0 {
			t.Fatalf("REGISTRATION ACCEPT carries the Rejected NSSAI IE too: % x", ra.RejectedNSSAI)
		}
		e.wantExtendedRejected(ra.ExtendedRejectedNSSAI, e2eNasA)
		e.uePeek(func(ue *amfctx.UEContext) {
			if !ue.ERNSSAISupported {
				t.Error("ER-NSSAI capability not stored on the UE context")
			}
		})
		e.finish()
	})

	t.Run("rel19 UE without ER-NSSAI: REGISTRATION ACCEPT keeps the Rejected NSSAI IE 0x11", func(t *testing.T) {
		e := newE2EEnv(t, newE2EAUSF(t, root, bin), "rel19", both)
		e.failSliceA("plain-ra-reject@nssaa")
		e.wantCUC(e.recvCUC(), []nas.SNSSAI{e2eNasB}, []nas.SNSSAI{e2eNasA}, e2eRejectedA)
		e.mustUL(nas.MsgTypeConfigurationUpdateComplete, nil)
		e.setER(true) // stale: the next request without the bit must reset it
		ra := e.periodicUpdate(false)
		if ra.ExtendedRejectedNSSAI != nil || len(ra.RejectedNSSAI) == 0 {
			t.Fatalf("REGISTRATION ACCEPT: Rejected NSSAI % x, Extended %+v; want only the Rejected NSSAI IE", ra.RejectedNSSAI, ra.ExtendedRejectedNSSAI)
		}
		e.finish()
	})

	// (9) TS 24.501 §4.6.2.4 b) / TS 23.502 §4.2.9.2 step 19a: every requested slice
	// failed but a default S-NSSAI (B, not subject to NSSAA) can be allowed: the CUC
	// carries it as the Allowed NSSAI (never an empty one) next to the Rejected NSSAI.
	t.Run("rel19 default S-NSSAI allowed in the CUC when the only requested slice failed", func(t *testing.T) {
		e := newE2EEnv(t, newE2EAUSF(t, root, bin), "rel19", both)
		e.uePeek(func(ue *amfctx.UEContext) { ue.AllowedNSSAI = nil }) // B was not requested: only A is pending
		e.failSliceA("default-allowed-reject@nssaa")
		e.wantCUC(e.recvCUC(), []nas.SNSSAI{e2eNasB}, []nas.SNSSAI{e2eNasA}, e2eRejectedA)
		e.uePeek(func(ue *amfctx.UEContext) {
			if !e2eSubHas(ue.AllowedNSSAI, e2eSliceB) || e2eSubHas(ue.AllowedNSSAI, e2eSliceA) || ue.State != amfctx.GMMRegistered {
				t.Errorf("allowed=%+v state=%v", ue.AllowedNSSAI, ue.State)
			}
		})
		e.finish()
	})

	// (10) T3522 on a silent UE (TS 24.501 §5.5.2.3.5 a): four retransmissions of the
	// DEREGISTRATION REQUEST, the fifth expiry aborts and de-registers the UE locally.
	t.Run("rel19 T3522: silent UE gets 4 retransmissions, then local de-registration", func(t *testing.T) {
		e := newE2EEnv(t, newE2EAUSF(t, root, bin), "rel19", onlyA)
		e.failSliceA("silent-ue-reject@nssaa")
		first := e.recvDereg()
		firstRaw, err := nas.EncodeDeregistrationRequestNW(first)
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= 4; i++ {
			if e.clk.liveOf(6*time.Second) != 1 {
				t.Fatalf("before expiry %d: T3522 live = %d", i, e.clk.liveOf(6*time.Second))
			}
			e.clk.last().f()
			e.run(func() {})
			re := e.recvDereg()
			raw, err := nas.EncodeDeregistrationRequestNW(re)
			if err != nil || !bytes.Equal(raw, firstRaw) {
				t.Fatalf("retransmission %d = % x, want % x (%v)", i, raw, firstRaw, err)
			}
		}
		e.silent("after 4 retransmissions")
		e.uePeek(func(ue *amfctx.UEContext) {
			if ue.State != amfctx.GMMDeregisteredInitiated {
				t.Errorf("state before the 5th expiry = %v", ue.State)
			}
		})
		e.clk.last().f() // fifth expiry
		e.run(func() {})
		if e.clk.liveOf(6*time.Second) != 0 {
			t.Fatal("T3522 still running after the abort")
		}
		e.silent("after the abort (local de-registration sends nothing to the UE)")
		e.udm.mu.Lock()
		if len(e.udm.dereg) != 1 {
			t.Errorf("UDM UECM de-registrations = %v, want 1", e.udm.dereg)
		}
		e.udm.mu.Unlock()
		if e.gnb.releaseCount() != 1 {
			t.Errorf("UE Context Release Command count = %d, want 1", e.gnb.releaseCount())
		}
		e.uePeek(func(ue *amfctx.UEContext) {
			if ue.State != amfctx.GMMDeregistered || !ue.PendingRemoval {
				t.Errorf("state = %v pendingRemoval = %v, want DEREGISTERED + pending removal", ue.State, ue.PendingRemoval)
			}
		})
		e.finish()
	})

	// (11) rel17 control (frozen): no T3522, legacy 0x7 spare nibble on a NW de-registration.
	t.Run("rel17 control: NW de-registration has no T3522 and the legacy spare nibble", func(t *testing.T) {
		e := newE2EEnv(t, newE2EAUSF(t, root, bin), "rel17", onlyA)
		e.run(func() {
			if err := e.h.SendNetworkDeregistration(context.Background(), e.ue, 0, 1, true); err != nil {
				t.Error(err)
			}
		})
		d := e.recv()
		raw, ok := d.msg.Body.(*nas.RawBody)
		if d.mt != nas.MsgTypeDeregistrationRequestNW || !ok || raw.Data[0] != 0x75 {
			t.Fatalf("DEREGISTRATION REQUEST = %+v, want first body octet 0x75", d.msg.Body)
		}
		if e.clk.count() != 0 {
			t.Fatalf("rel17 scheduled %d timers", e.clk.count())
		}
		e.mustUL(nas.MsgTypeDeregistrationAcceptNW, nil)
		e.finish()
	})

	// (7) rel17 control: legacy path unchanged.
	t.Run("rel17 control: legacy Nausf route, no T3575, frozen CUC", func(t *testing.T) {
		e := newE2EEnv(t, newE2EAUSF(t, root, bin), "rel17", both)
		e.registrationComplete()
		cmd := e.recvCommand()
		e.wantIdentityCommand(cmd, e2eNasA)
		if e.clk.count() != 0 {
			t.Fatalf("rel17 must not arm T3575: %d timers scheduled", e.clk.count())
		}
		e.complete(e2eNasA, e2eIdentity(e, cmd, "erin@nssaa"))
		id, _ := eap.Identifier(cmd.EAPMessage)
		e.wantEAPResult(e.recvResult(), e2eNasA, eap.CodeSuccess, id)
		cuc := e.recvCUC()
		// Frozen rel17 wire: Configuration update indication 0xD1 (ACK requested),
		// Allowed NSSAI IEI 0x15, no Rejected NSSAI IEI 0x11.
		raw, err := nas.EncodeConfigurationUpdateCommand(cuc)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) < 3 || raw[0] != 0xD1 || raw[1] != 0x15 || len(cuc.RejectedNSSAI) != 0 ||
			cuc.AllowedNSSAI == nil || !e2eHasSNSSAI(cuc.AllowedNSSAI.SNSSAIs, e2eNasA) {
			t.Fatalf("rel17 CUC = % x (%+v), want 0xD1, Allowed NSSAI incl. %+v, no Rejected NSSAI", raw, cuc, e2eNasA)
		}
		if e.clk.count() != 0 {
			t.Fatalf("rel17 scheduled %d timers", e.clk.count())
		}
		// Route: the legacy POST /nausf-nssaa/v1/{supi}/authenticate, not the TS 29.526 resource.
		lines := e.ausf.waitLog("NSSAA EAP relayed to AAA-S", 1)
		for _, l := range lines {
			if l["interface"] != "Nausf" || l["result"] != "EAP_SUCCESS" {
				t.Errorf("rel17 relay log = %v, want interface Nausf", l)
			}
		}
		e.finish()
	})

	t.Run("rel17 control: NSSAAF down rejects the slice, no PENDING, no retry on Service Request", func(t *testing.T) {
		ausf := newE2EAUSF(t, root, bin)
		e := newE2EEnv(t, ausf, "rel17", both)
		e.registrationComplete()
		cmd := e.recvCommand()
		ausf.stop()
		e.complete(e2eNasA, e2eIdentity(e, cmd, "frank@nssaa"))
		id, _ := eap.Identifier(cmd.EAPMessage)
		e.wantEAPResult(e.recvResult(), e2eNasA, eap.CodeFailure, id) // AMF-built EAP-Failure
		e.silent("rel17 sends no CUC after a failed slice (frozen)")
		e.uePeek(func(ue *amfctx.UEContext) {
			if len(ue.NSSAAPendingStatus) != 0 || !e2eSubHas(ue.RejectedNSSAI, e2eSliceA) || e2eSubHas(ue.AllowedNSSAI, e2eSliceA) {
				t.Errorf("rel17: pending=%+v rejected=%+v allowed=%+v", ue.NSSAAPendingStatus, ue.RejectedNSSAI, ue.AllowedNSSAI)
			}
		})
		ausf.start()
		e.uePeek(func(ue *amfctx.UEContext) { // even far past the rel19 interval
			for k := range ue.NSSAAPendingAt {
				delete(ue.NSSAAPendingAt, k)
			}
		})
		e.serviceRequest()
		if d := e.recv(); d.mt != nas.MsgTypeServiceAccept {
			t.Fatalf("got %#x, want SERVICE ACCEPT", byte(d.mt))
		}
		e.silent("rel17 Service Request: no NSSAA retry")
		if e.clk.count() != 0 {
			t.Fatalf("rel17 scheduled %d timers", e.clk.count())
		}
		e.finish()
	})
}

// waitAUSFReject waits for the AUSF's 403 SLICE_AUTH_REJECTED decision (log line).
func (e *e2eEnv) waitAUSFReject() {
	e.t.Helper()
	e2eEventually(e.t, "AUSF NSSAA rejected by AAA-S log", 5*time.Second, func() bool {
		for _, l := range e.ausf.logLines("NSSAA rejected by AAA-S") {
			if l["cause"] == "SLICE_AUTH_REJECTED" {
				return true
			}
		}
		return false
	})
}
