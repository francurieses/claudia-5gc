package ngap

// fuzz_test.go — native Go fuzz targets (go test -fuzz) for the NGAP PER codec front end
// (TS 38.413 §9.4, X.691 aligned PER through github.com/free5gc/aper) and for every N2 SM
// transfer the NGAP-PDU carries as OCTET STRING (CONTAINING ...): the PDU session transfers of
// TS 38.413 §9.3.4.1-§9.3.4.26 and the MBS transfers of §9.3.5.
//
// Properties checked on every input:
//   - no panic, and no hang (fuzzWatchdog);
//   - a nil error implies a non-nil result;
//   - one decode allocates at most decodeAllocBudget(len(input)) bytes: a make() sized from a
//     wire length must be bounded by the input, not only by the ASN.1 upper bound;
//   - when the decoded value re-encodes, the encoding is a fixpoint (it re-decodes and
//     re-encodes to the same octets): the general form of decode(encode(x)) == x.
//
// Seeds: testdata/corpus (REL19-4.4) and the transfer octet strings carried inside its PDUs.
// Minimised crashers live in testdata/fuzz/<FuzzName>/ and replay under a plain go test.
// Run one target: GOWORK=off go test -run=^$ -fuzz=^FuzzDecoder$ -fuzztime=5m ./shared/ngap/

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/free5gc/aper"
	aperlogger "github.com/free5gc/aper/logger"

	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

// aper logs most malformed inputs through its own logrus logger; level 0 (logrus.PanicLevel)
// keeps the fuzzing output readable and the executions fast.
func init() { aperlogger.SetLogLevel(0) }

// fuzzHangLimit bounds the time one input may take; a decoder still running after it is
// reported as a hang (the watchdog panics, which the fuzz engine records as a crasher).
const fuzzHangLimit = 10 * time.Second

// fuzzWatchdog arms the hang detector for one input; call the returned func when done.
func fuzzWatchdog(name string, in []byte) (stop func() bool) {
	t := time.AfterFunc(fuzzHangLimit, func() {
		panic(fmt.Sprintf("%s: still running after %s (hang) on input %x", name, fuzzHangLimit, in))
	})
	return t.Stop
}

// heapAllocs (cumulative heap bytes allocated by the process) is defined in iecount_test.go,
// which the allocation-bound regressions there also use.

// decodeAllocBudget is the heap one decode of n input octets may allocate. A decodable PDU
// needs at least 4 octets per IE (TS 38.413 §9.4.8 ProtocolIE-Field: 2-octet id, criticality
// and the open-type length octet), so legitimate decodes grow linearly with n. The 16 MiB
// floor leaves room for the one nested SEQUENCE OF a truncated PDU can still size from its
// wire count before the first item fails (largest nested list: 65535 extension items of
// 120 octets = 7.5 MiB; TestDecoderIEContainerAmplification covers the top-level container).
func decodeAllocBudget(n int) uint64 { return 16<<20 + 256*uint64(n) }

// checkAlloc fails when one decode of in allocated more than decodeAllocBudget(len(in)).
func checkAlloc(t *testing.T, name string, in []byte, before uint64) {
	t.Helper()
	if got, budget := heapAllocs()-before, decodeAllocBudget(len(in)); got > budget {
		t.Fatalf("%s: decoding %d octets allocated %d bytes (budget %d)\n input %x", name, len(in), got, budget, in)
	}
}

// checkFixpoint is the round-trip property for a value v decoded from in: when v re-encodes,
// the encoding must re-decode and re-encode to the same octets. Each decode reads a private
// copy: aper decodes fixed-size strings longer than two octets as slices of its input, and its
// encoder masks the unused bits of a BIT STRING in place, so encoding a decoded value rewrites
// the buffer it was decoded from.
func checkFixpoint(t *testing.T, name string, in []byte, v any,
	decode func([]byte) (any, error), encode func(any) ([]byte, error),
) {
	t.Helper()
	if belowRootSize(reflect.ValueOf(v), "") {
		return
	}
	enc, err := encode(v)
	if err != nil {
		return // e.g. a not comprehended IE (value Present 0) has no encoding
	}
	v2, err := decode(bytes.Clone(enc))
	if err != nil {
		t.Fatalf("%s: re-decode of the re-encoding failed: %v\n input %x\n enc   %x", name, err, in, enc)
	}
	enc2, err := encode(v2)
	if err != nil {
		t.Fatalf("%s: re-encode failed: %v\n enc %x", name, err, enc)
	}
	if !bytes.Equal(enc, enc2) {
		t.Fatalf("%s: encoding is not a fixpoint\n input %x\n enc   %x\n enc2  %x", name, in, enc, enc2)
	}
}

var (
	bitStringType   = reflect.TypeOf(aper.BitString{})
	octetStringType = reflect.TypeOf(aper.OctetString(nil))
)

// belowRootSize reports whether v holds a BIT STRING or OCTET STRING with an extensible SIZE
// constraint whose length is below the root lower bound (a size-extension value). aper's
// encoder treats only lengths above the root upper bound as extension values: below the lower
// bound it panics on an empty BIT STRING (ErrEncoderPanic, crasher 24a081b9ee21c079) and
// otherwise writes the root size, octets its own decoder rejects (crasher f844c4c65c3bb151).
// The AMF and SMF encode only values they build, so the round trip skips such values.
func belowRootSize(v reflect.Value, tag string) bool {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		return !v.IsNil() && belowRootSize(v.Elem(), tag)
	case reflect.Slice:
		if v.Type() == octetStringType {
			return sizeExtBelow(tag, int64(v.Len()))
		}
		for i := 0; i < v.Len(); i++ {
			if belowRootSize(v.Index(i), "") {
				return true
			}
		}
	case reflect.Struct:
		if v.Type() == bitStringType {
			return sizeExtBelow(tag, int64(v.Interface().(aper.BitString).BitLength))
		}
		for i := 0; i < v.NumField(); i++ {
			if belowRootSize(v.Field(i), v.Type().Field(i).Tag.Get("aper")) {
				return true
			}
		}
	}
	return false
}

// sizeExtBelow reports whether an aper tag has an extensible SIZE whose lower bound exceeds n.
func sizeExtBelow(tag string, n int64) bool {
	if !strings.Contains(","+tag+",", ",sizeExt,") {
		return false
	}
	lb, ok := aperTagInt(tag, "sizeLB:")
	return ok && n < lb
}

// marshalTransfer is aper.MarshalWithParams(v, "valueExt") returning an aper encoder panic as
// ErrEncoderPanic, as Encoder does for NGAP-PDUs. Only the round-trip step re-encodes decoded
// transfers; the AMF and SMF encode transfers they build themselves.
func marshalTransfer(v any) (b []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			b, err = nil, fmt.Errorf("%w: %v", ErrEncoderPanic, r)
		}
	}()
	return aper.MarshalWithParams(v, "valueExt")
}

// fuzzTransfer is one N2 SM transfer container type.
type fuzzTransfer struct {
	clause string // TS 38.413 clause defining the transfer
	typ    reflect.Type
}

// fuzzTransfers lists every transfer the NGAP-PDU carries as OCTET STRING (CONTAINING ...);
// TestFuzzTransfersCoverContainers keeps it complete. Every transfer is an extensible SEQUENCE,
// so it is decoded with the aper parameter "valueExt" (as the AMF and SMF do).
var fuzzTransfers = []fuzzTransfer{
	{"9.3.4.1", reflect.TypeOf(ngapType.PDUSessionResourceSetupRequestTransfer{})},
	{"9.3.4.2", reflect.TypeOf(ngapType.PDUSessionResourceSetupResponseTransfer{})},
	{"9.3.4.3", reflect.TypeOf(ngapType.PDUSessionResourceModifyRequestTransfer{})},
	{"9.3.4.4", reflect.TypeOf(ngapType.PDUSessionResourceModifyResponseTransfer{})},
	{"9.3.4.5", reflect.TypeOf(ngapType.PDUSessionResourceNotifyTransfer{})},
	{"9.3.4.6", reflect.TypeOf(ngapType.PDUSessionResourceModifyIndicationTransfer{})},
	{"9.3.4.7", reflect.TypeOf(ngapType.PDUSessionResourceModifyConfirmTransfer{})},
	{"9.3.4.8", reflect.TypeOf(ngapType.PathSwitchRequestTransfer{})},
	{"9.3.4.9", reflect.TypeOf(ngapType.PathSwitchRequestAcknowledgeTransfer{})},
	{"9.3.4.10", reflect.TypeOf(ngapType.HandoverCommandTransfer{})},
	{"9.3.4.11", reflect.TypeOf(ngapType.HandoverRequestAcknowledgeTransfer{})},
	{"9.3.4.12", reflect.TypeOf(ngapType.PDUSessionResourceReleaseCommandTransfer{})},
	{"9.3.4.13", reflect.TypeOf(ngapType.PDUSessionResourceNotifyReleasedTransfer{})},
	{"9.3.4.14", reflect.TypeOf(ngapType.HandoverRequiredTransfer{})},
	{"9.3.4.15", reflect.TypeOf(ngapType.PathSwitchRequestSetupFailedTransfer{})},
	{"9.3.4.16", reflect.TypeOf(ngapType.PDUSessionResourceSetupUnsuccessfulTransfer{})},
	{"9.3.4.17", reflect.TypeOf(ngapType.PDUSessionResourceModifyUnsuccessfulTransfer{})},
	{"9.3.4.18", reflect.TypeOf(ngapType.HandoverPreparationUnsuccessfulTransfer{})},
	{"9.3.4.19", reflect.TypeOf(ngapType.HandoverResourceAllocationUnsuccessfulTransfer{})},
	{"9.3.4.20", reflect.TypeOf(ngapType.PathSwitchRequestUnsuccessfulTransfer{})},
	{"9.3.4.21", reflect.TypeOf(ngapType.PDUSessionResourceReleaseResponseTransfer{})},
	{"9.3.4.22", reflect.TypeOf(ngapType.PDUSessionResourceModifyIndicationUnsuccessfulTransfer{})},
	{"9.3.4.23", reflect.TypeOf(ngapType.SecondaryRATDataUsageReportTransfer{})},
	{"9.3.4.24", reflect.TypeOf(ngapType.UEContextResumeRequestTransfer{})},
	{"9.3.4.25", reflect.TypeOf(ngapType.UEContextResumeResponseTransfer{})},
	{"9.3.4.26", reflect.TypeOf(ngapType.UEContextSuspendRequestTransfer{})},
	{"9.3.5.3", reflect.TypeOf(ngapType.MBSSessionSetupOrModRequestTransfer{})},
	{"9.3.5.5", reflect.TypeOf(ngapType.MBSSessionSetupOrModResponseTransfer{})},
	{"9.3.5.6", reflect.TypeOf(ngapType.MBSSessionSetupOrModFailureTransfer{})},
	{"9.3.5.7", reflect.TypeOf(ngapType.MBSDistributionSetupRequestTransfer{})},
	{"9.3.5.8", reflect.TypeOf(ngapType.MBSDistributionSetupResponseTransfer{})},
	{"9.3.5.9", reflect.TypeOf(ngapType.MBSDistributionSetupUnsuccessfulTransfer{})},
	{"9.3.5.10", reflect.TypeOf(ngapType.MBSDistributionReleaseRequestTransfer{})},
	{"9.3.5.11", reflect.TypeOf(ngapType.MulticastSessionActivationRequestTransfer{})},
	{"9.3.5.12", reflect.TypeOf(ngapType.MulticastSessionDeactivationRequestTransfer{})},
	{"9.3.5.13", reflect.TypeOf(ngapType.MulticastSessionUpdateRequestTransfer{})},
	{"9.3.5.14", reflect.TypeOf(ngapType.MBSSessionReleaseResponseTransfer{})},
}

// transferFieldAlias maps an OCTET STRING field whose name differs from the type it contains:
// handoverRequestTransfer is OCTET STRING (CONTAINING PDUSessionResourceSetupRequestTransfer)
// (TS 38.413 §9.4.5, PDUSessionResourceSetupItemHOReq).
var transferFieldAlias = map[string]string{
	"HandoverRequestTransfer": "PDUSessionResourceSetupRequestTransfer",
}

// transferIndex returns the fuzzTransfers index of the transfer an OCTET STRING field named
// field contains, or -1.
func transferIndex(field string) int {
	if a, ok := transferFieldAlias[field]; ok {
		field = a
	}
	for i, ft := range fuzzTransfers {
		if ft.typ.Name() == field {
			return i
		}
	}
	return -1
}

// collectTransfers walks a decoded value and calls add for every non-empty transfer octet
// string it carries (a struct field of type aper.OctetString whose name ends in "Transfer").
func collectTransfers(v reflect.Value, add func(idx int, b []byte)) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			collectTransfers(v.Elem(), add)
		}
	case reflect.Slice:
		if v.Type() == octetStringType {
			return
		}
		for i := 0; i < v.Len(); i++ {
			collectTransfers(v.Index(i), add)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			sf, fv := v.Type().Field(i), v.Field(i)
			if sf.Type == octetStringType && strings.HasSuffix(sf.Name, "Transfer") && fv.Len() > 0 {
				if idx := transferIndex(sf.Name); idx >= 0 {
					add(idx, bytes.Clone(fv.Bytes()))
				}
				continue
			}
			collectTransfers(fv, add)
		}
	}
}

// edgeSeeds are hand-made malformed NGAP-PDUs added to FuzzDecoder.
var edgeSeeds = [][]byte{
	{},
	{0x00},
	{0xff},
	{0x00, 0x15}, // InitiatingMessage NGSetup, truncated
	{0x00, 0x15, 0x00, 0x03, 0x00, 0xff, 0xff},       // NGSetupRequest declaring 65535 IEs, carrying none
	{0x00, 0x0e, 0x00, 0x03, 0x00, 0xff, 0xff},       // InitialContextSetupRequest declaring 65535 IEs
	{0x20, 0x0e, 0x00, 0x03, 0x00, 0xff, 0xff},       // successfulOutcome variant
	{0x00, 0x15, 0x00, 0x01, 0x00},                   // NGSetupRequest value without the IE count
	{0x80, 0x00, 0x00, 0x00},                         // NGAP-PDU extension alternative
	{0x60, 0x00, 0x00, 0x00},                         // CHOICE index 3 (out of root)
	{0x00, 0x09, 0x40, 0x03, 0x00, 0x00, 0x00},       // ErrorIndication, no IEs
	{0x00, 0x15, 0x00, 0x83, 0xff, 0x00, 0x00, 0x00}, // open-type length beyond the PDU
	{0x00, 0x15, 0x00, 0xc1, 0x00},                   // fragmented open-type length, truncated
}

// FuzzDecoder fuzzes Decoder (NGAP-PDU, TS 38.413 §9.4.3) with the round-trip fixpoint.
func FuzzDecoder(f *testing.F) {
	vecs, err := loadCorpus()
	if err != nil {
		f.Fatal(err)
	}
	for _, v := range vecs {
		if strings.HasPrefix(v.Name, "smf-") {
			continue
		}
		f.Add(v.Data)
		f.Add(v.Data[:len(v.Data)/2]) // truncated variant
	}
	for _, s := range edgeSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		defer fuzzWatchdog("FuzzDecoder", b)()
		before := heapAllocs()
		pdu, err := Decoder(bytes.Clone(b))
		checkAlloc(t, "Decoder", b, before)
		if err != nil {
			return
		}
		if pdu == nil {
			t.Fatal("Decoder: nil PDU with nil error")
		}
		checkFixpoint(t, "NGAP-PDU", b, pdu,
			func(in []byte) (any, error) { return Decoder(in) },
			func(v any) ([]byte, error) { return Encoder(*v.(*ngapType.NGAPPDU)) })
	})
}

// FuzzTransfer fuzzes the decode of every N2 SM transfer (fuzzTransfers; sel picks the type)
// with the same properties as FuzzDecoder.
func FuzzTransfer(f *testing.F) {
	vecs, err := loadCorpus()
	if err != nil {
		f.Fatal(err)
	}
	add := func(idx int, b []byte) {
		f.Add(uint8(idx), b)
		f.Add(uint8(idx), b[:len(b)/2])
	}
	for _, v := range vecs {
		tn, err := transferTypeName(v.Name)
		if err != nil {
			f.Fatal(err)
		}
		if tn != "" {
			if idx := transferIndex(tn); idx >= 0 {
				add(idx, v.Data)
			}
			continue
		}
		pdu, err := Decoder(v.Data)
		if err != nil {
			f.Fatalf("%s: %v", v.Name, err)
		}
		collectTransfers(reflect.ValueOf(pdu), add)
	}
	for i := range fuzzTransfers {
		f.Add(uint8(i), []byte{})
		f.Add(uint8(i), []byte{0x00})
		f.Add(uint8(i), []byte{0x40, 0xff, 0xff}) // optional bitmap set, then a 65535 count
	}
	f.Fuzz(func(t *testing.T, sel uint8, b []byte) {
		ft := fuzzTransfers[int(sel)%len(fuzzTransfers)]
		name := ft.typ.Name()
		defer fuzzWatchdog("FuzzTransfer/"+name, b)()
		decode := func(in []byte) (any, error) {
			v := reflect.New(ft.typ)
			return v.Interface(), aper.UnmarshalWithParams(in, v.Interface(), "valueExt")
		}
		before := heapAllocs()
		v, err := decode(bytes.Clone(b))
		checkAlloc(t, name, b, before)
		if err != nil {
			return
		}
		checkFixpoint(t, name, b, v, decode,
			func(v any) ([]byte, error) { return marshalTransfer(reflect.ValueOf(v).Elem().Interface()) })
	})
}

// TestFuzzTransfersCoverContainers fails when the generated NGAP-PDU gains a transfer OCTET
// STRING (a field of type aper.OctetString named *Transfer) that fuzzTransfers does not list.
func TestFuzzTransfersCoverContainers(t *testing.T) {
	seen := map[reflect.Type]bool{}
	missing := map[string]bool{}
	var walk func(tp reflect.Type)
	walk = func(tp reflect.Type) {
		for tp.Kind() == reflect.Pointer || tp.Kind() == reflect.Slice && tp != octetStringType {
			tp = tp.Elem()
		}
		if tp.Kind() != reflect.Struct || seen[tp] {
			return
		}
		seen[tp] = true
		for i := 0; i < tp.NumField(); i++ {
			sf := tp.Field(i)
			if sf.Type == octetStringType && strings.HasSuffix(sf.Name, "Transfer") {
				if transferIndex(sf.Name) < 0 {
					missing[tp.Name()+"."+sf.Name] = true
				}
				continue
			}
			walk(sf.Type)
		}
	}
	walk(reflect.TypeOf(ngapType.NGAPPDU{}))
	for m := range missing {
		t.Errorf("transfer container %s has no fuzzTransfers entry", m)
	}
}
