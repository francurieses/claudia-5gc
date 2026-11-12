// Package ngap is the thin NGAP (TS 38.413) PER codec front end of the 5GC. The message types live
// in the generated package ngapType (from the TS 38.413 clause 9.4 ASN.1); the ASN.1 Aligned PER
// engine stays github.com/free5gc/aper (CLAUDE.md "Protocol Encoding Rules"). Decoder and Encoder
// keep the signatures of github.com/free5gc/ngap so call sites can switch imports unchanged.
package ngap

//go:generate ../../scripts/gen-ngap.sh

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/free5gc/aper"

	"github.com/francurieses/claudia-5gc/shared/ngap/ngapType"
)

// PPID is the SCTP payload protocol identifier of NGAP (60) in network byte order (TS 38.412 §7).
const PPID uint32 = 0x3c000000

// pduParams are the aper parameters of the NGAP-PDU CHOICE: extensible, three root alternatives
// (initiatingMessage, successfulOutcome, unsuccessfulOutcome) [TS 38.413 §9.4.1].
const pduParams = "valueExt,valueLB:0,valueUB:2"

// ErrIEContainerCount reports an NGAP-PDU whose message IE container declares more IEs than the
// message value can hold, or whose value ends before the count: a transfer syntax error
// (TS 38.413 §10.2).
var ErrIEContainerCount = errors.New("ngap: IE container count exceeds the message value")

// minIEOctets is the smallest aligned PER encoding of one ProtocolIE-Field (TS 38.413 §9.4.8):
// the 2-octet id, the 2-bit criticality padded to the octet boundary of the open-type value,
// and the value's length determinant.
const minIEOctets = 4

// ieContainerLB maps (NGAP-PDU alternative, procedure code) to the SIZE lower bound of the
// message's IE container, for every message the generated types decode (TS 38.413 §9.4.3,
// §9.4.4). The alternative index is 0 initiatingMessage, 1 successfulOutcome,
// 2 unsuccessfulOutcome.
var ieContainerLB = buildIEContainerLB()

// buildIEContainerLB reads ieContainerLB from the ngapType struct tags: each message value
// field carries referenceFieldValue:<procedure code> and points to a struct whose only field is
// the container, a struct whose only field is the List with its SIZE bounds. Only containers
// with SIZE upper bound maxProtocolIEs/maxPrivateIEs (65535, TS 38.413 §9.4.7), whose count is
// two aligned octets, are listed.
func buildIEContainerLB() map[[2]int64]int {
	m := map[[2]int64]int{}
	for alt, vt := range []reflect.Type{
		reflect.TypeOf(ngapType.InitiatingMessageValue{}),
		reflect.TypeOf(ngapType.SuccessfulOutcomeValue{}),
		reflect.TypeOf(ngapType.UnsuccessfulOutcomeValue{}),
	} {
		for i := 0; i < vt.NumField(); i++ {
			f := vt.Field(i)
			code, ok := aperTagInt(f.Tag.Get("aper"), "referenceFieldValue:")
			if !ok || f.Type.Kind() != reflect.Pointer || f.Type.Elem().Kind() != reflect.Struct ||
				f.Type.Elem().NumField() != 1 {
				continue
			}
			c := f.Type.Elem().Field(0).Type
			if c.Kind() != reflect.Struct || c.NumField() != 1 || c.Field(0).Type.Kind() != reflect.Slice {
				continue
			}
			tag := c.Field(0).Tag.Get("aper")
			lb, okLB := aperTagInt(tag, "sizeLB:")
			ub, okUB := aperTagInt(tag, "sizeUB:")
			if okLB && okUB && ub == 65535 && (lb == 0 || lb == 1) {
				m[[2]int64{int64(alt), code}] = int(lb)
			}
		}
	}
	return m
}

// aperTagInt returns the integer of the "<key><n>" item of an aper struct tag.
func aperTagInt(tag, key string) (int64, bool) {
	for _, p := range strings.Split(tag, ",") {
		if v, ok := strings.CutPrefix(p, key); ok {
			n, err := strconv.ParseInt(v, 10, 64)
			return n, err == nil
		}
	}
	return 0, false
}

// ieContainerCount locates the IE container of the message carried by an NGAP-PDU and returns
// its declared IE count and the octet length of the message value (an upper bound when the
// open-type length is fragmented). placed is false for a PDU it cannot place (extension
// alternative, procedure the generated types do not decode, header or open type cut short),
// which is left to aper.
//
// Layout (aligned PER, TS 38.413 §9.4.3, §9.4.4, §9.4.8): octet 0 = CHOICE extension bit and
// 2-bit alternative index, octet 1 = procedureCode, octet 2 = 2-bit criticality, octet 3 = the
// open-type length (one octet below 128, two octets 10xxxxxx, else fragmented with at least
// 16384 value octets); the value starts with the message extension bit, padded, and the
// 2-octet container count. count is -1 when the value is too short to hold it.
func ieContainerCount(b []byte) (count, valueLen int, placed bool) {
	if len(b) < 4 || b[0]&0x80 != 0 {
		return 0, 0, false
	}
	lb, ok := ieContainerLB[[2]int64{int64(b[0] >> 5), int64(b[1])}]
	if !ok {
		return 0, 0, false
	}
	off, n := 4, len(b)-4 // value offset and length (an upper bound if fragmented)
	switch l := b[3]; {
	case l&0x80 == 0:
		n = int(l)
	case l&0xc0 == 0x80:
		if len(b) < 5 {
			return 0, 0, false
		}
		off, n = 5, int(l&0x3f)<<8|int(b[4])
	}
	if off+n > len(b) {
		return 0, 0, false // aper reports the truncated open type
	}
	if n < 3 {
		return -1, n, true
	}
	return (int(b[off+1])<<8 | int(b[off+2])) + lb, n, true
}

// checkIEContainerCount bounds the IE count of the message carried by an NGAP-PDU by the
// octets of the message value, before aper sizes a slice from that count: aper allocates
// count x item size (up to 65535 x 472 octets = 29.5 MiB for InitialContextSetupRequest) before
// it reads the first item, so a 7-octet PDU made the decoder allocate tens of MiB. It also
// rejects a value too short to hold the count, which aper decodes as an empty IE list.
func checkIEContainerCount(b []byte) error {
	count, n, placed := ieContainerCount(b)
	switch {
	case !placed:
		return nil
	case count < 0:
		return fmt.Errorf("%w: %d-octet message value has no IE count", ErrIEContainerCount, n)
	case count > (n-3)/minIEOctets:
		return fmt.Errorf("%w: %d IEs declared, room for %d", ErrIEContainerCount, count, (n-3)/minIEOctets)
	}
	return nil
}

// Decoder decodes an NGAP-PDU from its ASN.1 Aligned PER encoding.
func Decoder(b []byte) (*ngapType.NGAPPDU, error) {
	pdu := &ngapType.NGAPPDU{}
	if err := checkIEContainerCount(b); err != nil {
		return pdu, fmt.Errorf("ngap: decode NGAP-PDU: %w", err)
	}
	if err := aper.UnmarshalWithParams(b, pdu, pduParams); err != nil {
		return pdu, fmt.Errorf("ngap: decode NGAP-PDU: %w", err)
	}
	return pdu, nil
}

// ErrEncoderPanic reports a value the aper encoder failed on by panicking instead of returning
// an error. Found by FuzzDecoder: a decodable BIT STRING (SIZE(16, ...)) received in the size
// extension form with fewer bits than the root size (TS 38.413 §9.3.1.86 UE Security
// Capabilities) made aper index an empty slice.
var ErrEncoderPanic = errors.New("ngap: aper encoder panic")

// Encoder encodes an NGAP-PDU to ASN.1 Aligned PER. It never panics: an aper encoder panic is
// returned as ErrEncoderPanic.
func Encoder(pdu ngapType.NGAPPDU) (b []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			b, err = nil, fmt.Errorf("ngap: encode NGAP-PDU: %w: %v", ErrEncoderPanic, r)
		}
	}()
	b, err = aper.MarshalWithParams(pdu, pduParams)
	if err != nil {
		return nil, fmt.Errorf("ngap: encode NGAP-PDU: %w", err)
	}
	return b, nil
}
