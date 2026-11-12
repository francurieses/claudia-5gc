package ngap

// fuzz_test.go — native Go fuzz targets (go test -fuzz) for the AMF NGAP receive path
// (TS 38.413): the decode into the AMF Message (DecodeNGAPPDU: aper, buildMessage and every
// extractor), the abstract syntax scan (TS 38.413 §10.3), the full dispatch of a gNB-originated
// PDU through the handlers against a fake SCTP association, the AMF checks of PDU session
// resource transfers (TS 38.413 §9.3.4) and the PWS page decoder (TS 23.041 §9.4.2.2.5).
//
// Properties: no panic (also in goroutines the handlers start), no hang (fuzzWatchdog), a
// decode allocates at most decodeAllocBudget, a nil error implies a result, and the AMF never
// emits an NGAP PDU it cannot decode itself, never with a PPID other than 60 (TS 38.412 §7),
// and never answers an ERROR INDICATION with one (TS 38.413 §10.5).
// Seeds: the NGAP corpus of shared/ngap (testdata/corpus, REL19-4.4).
// Run one target: GOWORK=off go test -run=^$ -fuzz=^FuzzDispatchNGAP$ -fuzztime=5m ./nf/amf/internal/ngap/

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/metrics"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/free5gc/aper"
	aperlogger "github.com/free5gc/aper/logger"
	"github.com/ishidawataru/sctp"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	libngap "github.com/francurieses/claudia-5gc/shared/ngap"
	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

// aper logs most malformed inputs through its own logrus logger; level 0 (logrus.PanicLevel)
// keeps the fuzzing output readable and the executions fast.
func init() { aperlogger.SetLogLevel(0) }

// fuzzCorpusGlob is the shared NGAP equivalence corpus (one hex PDU or transfer per file).
const fuzzCorpusGlob = "../../../../shared/ngap/testdata/corpus/*.hex"

// fuzzHangLimit bounds one input; a target still running after it is reported as a hang (the
// watchdog panics, which the fuzz engine records as a crasher).
const fuzzHangLimit = 10 * time.Second

// fuzzWatchdog arms the hang detector for one input; call the returned func when done.
func fuzzWatchdog(name string, in []byte) (stop func() bool) {
	t := time.AfterFunc(fuzzHangLimit, func() {
		panic(fmt.Sprintf("%s: still running after %s (hang) on input %x", name, fuzzHangLimit, in))
	})
	return t.Stop
}

// fuzzHeapAllocs returns the cumulative heap bytes allocated by the process (runtime/metrics,
// no stop-the-world).
func fuzzHeapAllocs() uint64 {
	s := [1]metrics.Sample{{Name: "/gc/heap/allocs:bytes"}}
	metrics.Read(s[:])
	return s[0].Value.Uint64()
}

// fuzzAllocBudget is the heap one decode of n octets may allocate: linear in n (a decodable PDU
// needs at least 4 octets per IE, TS 38.413 §9.4.8) plus room for one nested SEQUENCE OF that
// aper sizes from its wire count before failing (at most 7.5 MiB, see shared/ngap/fuzz_test.go).
func fuzzAllocBudget(n int) uint64 { return 16<<20 + 256*uint64(n) }

// loadFuzzCorpus returns the corpus vectors by file name (without .hex): NGAP-PDUs
// (amf-*, pcap-*) and N2 SM transfers (smf-<TransferType>-*).
func loadFuzzCorpus(tb testing.TB) map[string][]byte {
	tb.Helper()
	files, err := filepath.Glob(fuzzCorpusGlob)
	if err != nil || len(files) == 0 {
		tb.Fatalf("no corpus at %s: %v", fuzzCorpusGlob, err)
	}
	out := map[string][]byte{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			tb.Fatal(err)
		}
		b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			tb.Fatalf("%s: %v", f, err)
		}
		out[strings.TrimSuffix(filepath.Base(f), ".hex")] = b
	}
	return out
}

// addPDUSeeds adds every corpus NGAP-PDU, its truncated half, and edge cases to f.
func addPDUSeeds(f *testing.F) {
	for name, b := range loadFuzzCorpus(f) {
		if strings.HasPrefix(name, "smf-") {
			continue
		}
		f.Add(b)
		f.Add(b[:len(b)/2])
	}
	for _, s := range [][]byte{
		{},
		{0x00, 0x09, 0x40}, // ERROR INDICATION, truncated
		{0x00, 0x09, 0x40, 0x03, 0x00, 0x00, 0x00}, // ERROR INDICATION without IEs
		{0x00, 0x15, 0x00, 0x03, 0x00, 0xff, 0xff}, // NG SETUP REQUEST declaring 65535 IEs
		{0x00, 0x15, 0x00, 0x01, 0x00},             // NG SETUP REQUEST value without the IE count
		{0x00, 0xfe, 0x00, 0x03, 0x00, 0x00, 0x00}, // unknown procedure code, criticality reject
		{0x00, 0xfe, 0x40, 0x03, 0x00, 0x00, 0x00}, // unknown procedure code, criticality ignore
	} {
		f.Add(s)
	}
}

// FuzzDecodeNGAPPDU fuzzes the AMF decode (DecodeNGAPPDU and the dispatch variant
// decodeNGAPPDUWithRaw: aper plus every extractor) and the abstract syntax scan of TS 38.413
// §10.3, whose reflection walk must never panic.
func FuzzDecodeNGAPPDU(f *testing.F) {
	addPDUSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		defer fuzzWatchdog("FuzzDecodeNGAPPDU", b)()
		before := fuzzHeapAllocs()
		msg, err := DecodeNGAPPDU(bytes.Clone(b))
		if got, budget := fuzzHeapAllocs()-before, fuzzAllocBudget(len(b)); got > budget {
			t.Fatalf("decoding %d octets allocated %d bytes (budget %d)", len(b), got, budget)
		}
		msg2, pdu, err2 := decodeNGAPPDUWithRaw(bytes.Clone(b))
		if (err == nil) != (err2 == nil) {
			t.Fatalf("DecodeNGAPPDU err=%v but decodeNGAPPDUWithRaw err=%v", err, err2)
		}
		if err != nil {
			return
		}
		if msg == nil || msg2 == nil || pdu == nil {
			t.Fatal("nil result with nil error")
		}
		if msg.Type == 0 && msg.ProcedureCode == ProcErrorIndication && !peekErrorIndication(b) {
			t.Fatalf("decoded an ERROR INDICATION that peekErrorIndication does not identify: %x", b)
		}
		if unknownProcedure(pdu) {
			return
		}
		if _, _, _, err := scanAbstractSyntax(msg2, pdu); err != nil && strings.Contains(err.Error(), "panic") {
			t.Fatalf("abstract syntax scan panicked: %v", err)
		}
	})
}

// fuzzGNBAddr is the association key of the fake gNB of the dispatch harness.
const fuzzGNBAddr = "192.0.2.1:38412"

// fuzzRANIDs are the RAN UE NGAP IDs of the UE contexts the dispatch harness creates (AMF UE
// NGAP IDs 1..6), matching the UE NGAP ID pairs the pcap corpus vectors carry.
var fuzzRANIDs = []int64{1, 2, 3, 4, 5, 6}

// fuzzTransport records what the AMF writes to the fake SCTP association.
type fuzzTransport struct {
	mu   sync.Mutex
	pdus [][]byte
	ppid []uint32
}

func (f *fuzzTransport) write(pdu []byte, info *sctp.SndRcvInfo) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pdus = append(f.pdus, bytes.Clone(pdu))
	f.ppid = append(f.ppid, info.PPID)
	return len(pdu), nil
}

// fuzzNAS (accepts every NAS PDU; the NAS layer has its own fuzz targets in shared/nas) is
// defined in fuzz_regression_test.go, which also builds a Server with it.

// newDispatchHarness returns an AMF NGAP server with one NG-ready fake gNB and the UE contexts
// of fuzzRANIDs, built fresh for every input so each input replays on its own.
func newDispatchHarness() (*Server, *GNBContext, *amfctx.Manager, *fuzzTransport) {
	mgr := amfctx.NewManager(amfctx.AMFIdentity{}, nil, nil, nil)
	cfg := AMFConfig{Name: "amf-fuzz", MCC: "001", MNC: "01", RegionID: 1, SetID: 1, AMFID: 1,
		SNSSAIs: []amfctx.SNSSAISubscribed{{SST: 1, SD: "000001"}}}
	srv := NewServer("", mgr, fuzzNAS{}, cfg, slog.New(slog.DiscardHandler))
	tr := &fuzzTransport{}
	gnb := &GNBContext{UEs: map[int64]*amfctx.UEContext{}, IdleUEs: map[int64]*amfctx.UEContext{}}
	gnb.SetTransportForTest(fuzzGNBAddr, tr.write)
	srv.AddGNBForTest(fuzzGNBAddr, gnb)
	srv.CompleteNGSetupForTest(gnb)
	for _, ran := range fuzzRANIDs {
		ue := mgr.AllocateUEContext(ran)
		ue.GNBAddr = fuzzGNBAddr
		gnb.UEs[ran] = ue
	}
	return srv, gnb, mgr, tr
}

// FuzzDispatchNGAP feeds one gNB-originated PDU through the AMF dispatcher exactly as the SCTP
// read loop does (decode, abstract syntax check, handler) and waits for the per-UE serial
// queues to drain.
func FuzzDispatchNGAP(f *testing.F) {
	addPDUSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		defer fuzzWatchdog("FuzzDispatchNGAP", b)()
		srv, gnb, mgr, tr := newDispatchHarness()
		srv.DispatchNGAPForTest(context.Background(), gnb, bytes.Clone(b))
		for id := int64(1); id <= int64(len(fuzzRANIDs))+4; id++ { // +4: UEs a handler created
			if _, ok := mgr.GetByNGAPId(id); ok && !srv.WaitUESerialForTest(id) {
				t.Fatalf("UE %d serial queue did not drain", id)
			}
		}
		tr.mu.Lock()
		defer tr.mu.Unlock()
		inEI := peekErrorIndication(b)
		for i, out := range tr.pdus {
			if tr.ppid[i] != ngapPPID {
				t.Fatalf("outbound PDU %d sent with PPID %d, want %d", i, tr.ppid[i], ngapPPID)
			}
			p, err := libngap.Decoder(out)
			if err != nil {
				t.Fatalf("AMF sent an undecodable PDU %x: %v\n input %x", out, err, b)
			}
			if inEI && p.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
				p.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeErrorIndication {
				t.Fatalf("ERROR INDICATION answered with an ERROR INDICATION %x\n input %x", out, b)
			}
		}
	})
}

// causeTransfer encodes a HandoverResourceAllocationUnsuccessfulTransfer carrying c.
func causeTransfer(tb testing.TB, c ngapType.Cause) []byte {
	tb.Helper()
	b, err := aper.MarshalWithParams(ngapType.HandoverResourceAllocationUnsuccessfulTransfer{Cause: c}, "valueExt")
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// FuzzTransferChecks fuzzes the AMF decode checks of PDU session resource transfers: the
// validity checks of SMF-supplied transfers (smf_leg.go) and hoResAllocFailCause on a target's
// Handover Resource Allocation Unsuccessful Transfer (TS 38.413 §9.3.4.19), whose Cause the
// AMF re-encodes into the HANDOVER COMMAND: every decodable Cause must re-encode and decode
// back unchanged, else BuildHandoverCommand returns nil and no HANDOVER COMMAND is sent.
func FuzzTransferChecks(f *testing.F) {
	for name, b := range loadFuzzCorpus(f) {
		if strings.HasPrefix(name, "smf-") {
			f.Add(b)
			f.Add(b[:len(b)/2])
		}
	}
	for _, c := range []ngapType.Cause{
		buildCause(ngapType.CausePresentRadioNetwork, int64(ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem)),
		buildCause(ngapType.CausePresentTransport, 0),
		buildCause(ngapType.CausePresentNas, 0),
		buildCause(ngapType.CausePresentProtocol, int64(ngapType.CauseProtocolPresentSemanticError)),
		buildCause(ngapType.CausePresentMisc, 0),
		buildCause(ngapType.CausePresentRadioNetwork, 49), // extension value (root is 0..44)
	} {
		f.Add(causeTransfer(f, c))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		defer fuzzWatchdog("FuzzTransferChecks", b)()
		before := fuzzHeapAllocs()
		in := bytes.Clone(b)
		_ = validPathSwitchAckTransfer(in)
		_ = validPathSwitchUnsuccessfulTransfer(in)
		_ = validHandoverCommandTransfer(in)
		_ = validPDUResSetupRequestTransfer(in)
		_ = validHandoverPrepUnsuccessfulTransfer(in)
		p, v, ok := hoResAllocFailCause(in)
		if got, budget := fuzzHeapAllocs()-before, 6*fuzzAllocBudget(len(b)); got > budget {
			t.Fatalf("six decodes of %d octets allocated %d bytes (budget %d)", len(b), got, budget)
		}
		if !ok {
			return
		}
		if p < ngapType.CausePresentRadioNetwork || p > ngapType.CausePresentMisc {
			t.Fatalf("hoResAllocFailCause ok with Cause choice %d", p)
		}
		tb, err := aper.MarshalWithParams(ngapType.HandoverPreparationUnsuccessfulTransfer{Cause: buildCause(p, v)}, "valueExt")
		if err != nil {
			t.Fatalf("relayed Cause (%d,%d) does not re-encode: %v", p, v, err)
		}
		var back ngapType.HandoverPreparationUnsuccessfulTransfer
		if err := aper.UnmarshalWithParams(tb, &back, "valueExt"); err != nil {
			t.Fatalf("re-encoded Cause (%d,%d) does not decode: %v", p, v, err)
		}
		if p2, v2, ok2 := causeFromNGAP(back.Cause); !ok2 || p2 != p || v2 != v {
			t.Fatalf("relayed Cause (%d,%d) came back as (%d,%d,%v)", p, v, p2, v2, ok2)
		}
	})
}

// FuzzDecodeWarningMessageContentPages fuzzes the PWS Warning Message Contents page decoder
// (TS 23.041 §9.4.2.2.5) for every DCS alphabet, and checks decode(encode(text)) == text for
// the 8-bit alphabet and for UCS2 BMP text.
func FuzzDecodeWarningMessageContentPages(f *testing.F) {
	for _, dcs := range []byte{0x0f, 0x11, 0x44, 0x48} { // GSM7, UCS2+language, 8-bit, UCS2
		f.Add(dcs, encodeWarningMessageContentPages(dcs, "en", []byte("Earthquake warning: move to higher ground")))
		f.Add(dcs, []byte{0x02})
	}
	f.Fuzz(func(t *testing.T, dcs byte, wire []byte) {
		defer fuzzWatchdog("FuzzDecodeWarningMessageContentPages", wire)()
		out := DecodeWarningMessageContentPages(dcs, wire)
		if len(out) > 3*len(wire) { // at most one 3-octet UTF-8 rune per input octet
			t.Fatalf("decoded %d octets from %d", len(out), len(wire))
		}
		// Round trip with wire as the text: 8-bit is lossless up to 15 pages of 82 octets.
		text := wire
		if len(text) > cbsPageContentLength*cbsMaxPages {
			text = text[:cbsPageContentLength*cbsMaxPages]
		}
		if got := DecodeWarningMessageContentPages(0x44, encodeWarningMessageContentPages(0x44, "", text)); !bytes.Equal(got, text) {
			t.Fatalf("8-bit round trip: got %x, want %x", got, text)
		}
		if ucs2RoundTrips(text) {
			if got := DecodeWarningMessageContentPages(0x48, encodeWarningMessageContentPages(0x48, "", text)); !bytes.Equal(got, text) {
				t.Fatalf("UCS2 round trip: got %q, want %q", got, text)
			}
		}
	})
}

// ucs2RoundTrips reports whether text is valid UTF-8 of BMP characters other than U+0000 that
// fits the 15 UCS2 pages (41 characters each), the domain where UCS2 encoding is lossless.
func ucs2RoundTrips(text []byte) bool {
	if !utf8.Valid(text) || utf8.RuneCount(text) > ucs2MaxCharsPerPage*cbsMaxPages {
		return false
	}
	for _, r := range string(text) {
		if r == 0 || r > 0xffff {
			return false
		}
	}
	return true
}
