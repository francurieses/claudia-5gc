package lpp

// lpp_tshark_test.go — the LMF-009 conformance oracle: every golden LPP PDU
// this package emits is dissected by the Wireshark/tshark LPP dissector and
// must produce ZERO malformed fields plus the expected per-field values.
//
// # How the PDU reaches the LPP dissector
//
// tshark 4.6.4 has no direct decode-as handle for standalone LPP on a UDP
// port (the "lpp" dissector is not registered in the udp.port decode-as
// table — verified at implementation). The PDU is therefore embedded in its
// real production carrier: a plain (unciphered) NAS-5GS DL NAS Transport
// with payload container type 0x03 (TS 24.501 §8.7.4/§9.11.3.40), wrapped in
// an NGAP DownlinkNASTransport (TS 38.413 §8.6.2, built with free5gc/ngap —
// test-only import, the production codec in this package has no free5gc
// dependency), written to a synthetic pcap via `text2pcap -S 38412,38412,60`
// (SCTP DATA, PPID 60 per TS 38.412 §7) and dissected with `tshark -V`. The
// dissection chain SCTP → NGAP → NAS-5GS → LPP exercises the exact live
// path, except unciphered (the live N2 capture is NEA2-ciphered post-SMC, so
// the inner LPP octets are only provable via this standalone oracle — see
// docs/procedures/LPPRelay.md §Validation approach).
//
// The test SKIPS when tshark or text2pcap is not installed; on the reference
// machine (tshark 4.6.4) it must pass.
//
// # [VERIFY] resolutions recorded by this oracle (2026-07-05)
//
//   - codePhaseRMSError bit packing: exponent in the 3 MSBs, mantissa in the
//     3 LSBs (k = 8·y + x). Confirmed: the dissector extracts exponent =
//     (k>>3)&7 / mantissa = k&7, and its k=63 branch prints "112 <= P" =
//     0.5·(1 + 6/8)·2^7 — the doc's pin k=20 ⇒ exactly 3.0 m stands. (The
//     dissector's general-branch range display collapses the mantissa term
//     via C integer division — a Wireshark display quirk, not an encoding
//     difference.)
//   - referenceTimeUnc scaling: value 32 dissects as "32.607413us" =
//     0.5·(1.14^32 − 1) µs — the doc's r = 0.5·(1.14^K − 1) µs is confirmed.
//   - Longitude floor: raw −172610 dissects as −3.703809° for the −3.7038°
//     Madrid anchor — floor toward −∞ (not truncation to −172609) confirmed.

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/free5gc/aper"
	libngap "github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

// requireTools skips the test when the oracle toolchain is missing.
func requireTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"tshark", "text2pcap"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed — tshark oracle skipped", tool)
		}
	}
}

// wrapInNGAP builds the carrier frame: plain DL NAS Transport (EPD 0x7E,
// SHT 0x00, MsgType 0x68, PCT 0x03, LV-E length) inside an NGAP
// DownlinkNASTransport (ProcCode 4).
func wrapInNGAP(t *testing.T, lppPDU []byte) []byte {
	t.Helper()
	nasPDU := []byte{0x7E, 0x00, 0x68, 0x03, byte(len(lppPDU) >> 8), byte(len(lppPDU))}
	nasPDU = append(nasPDU, lppPDU...)

	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{Value: ngapType.ProcedureCodeDownlinkNASTransport},
			Criticality:   ngapType.Criticality{Value: ngapType.CriticalityPresentIgnore},
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentDownlinkNASTransport,
				DownlinkNASTransport: &ngapType.DownlinkNASTransport{
					ProtocolIEs: ngapType.ProtocolIEContainerDownlinkNASTransportIEs{
						List: []ngapType.DownlinkNASTransportIEs{
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDAMFUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.DownlinkNASTransportIEsValue{
									Present:     ngapType.DownlinkNASTransportIEsPresentAMFUENGAPID,
									AMFUENGAPID: &ngapType.AMFUENGAPID{Value: 1},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDRANUENGAPID},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.DownlinkNASTransportIEsValue{
									Present:     ngapType.DownlinkNASTransportIEsPresentRANUENGAPID,
									RANUENGAPID: &ngapType.RANUENGAPID{Value: 1},
								},
							},
							{
								Id:          ngapType.ProtocolIEID{Value: ngapType.ProtocolIEIDNASPDU},
								Criticality: ngapType.Criticality{Value: ngapType.CriticalityPresentReject},
								Value: ngapType.DownlinkNASTransportIEsValue{
									Present: ngapType.DownlinkNASTransportIEsPresentNASPDU,
									NASPDU:  &ngapType.NASPDU{Value: aper.OctetString(nasPDU)},
								},
							},
						},
					},
				},
			},
		},
	}
	b, err := libngap.Encoder(pdu)
	if err != nil {
		t.Fatalf("ngap encode: %v", err)
	}
	return b
}

// dissect runs the golden PDU through text2pcap + tshark -V and returns the
// verbose dissection text.
func dissect(t *testing.T, lppPDU []byte) string {
	t.Helper()
	dir := t.TempDir()
	frame := wrapInNGAP(t, lppPDU)

	var hexdump strings.Builder
	hexdump.WriteString("0000")
	for _, b := range frame {
		fmt.Fprintf(&hexdump, " %02x", b)
	}
	hexdump.WriteString("\n")

	txt := filepath.Join(dir, "frame.txt")
	pcap := filepath.Join(dir, "frame.pcap")
	if err := os.WriteFile(txt, []byte(hexdump.String()), 0o644); err != nil {
		t.Fatalf("write hexdump: %v", err)
	}
	// SCTP DATA chunk with src/dst port 38412 and PPID 60 (TS 38.412 §7) —
	// tshark auto-dissects NGAP → NAS-5GS → LPP.
	if out, err := exec.Command("text2pcap", "-q", "-S", "38412,38412,60", txt, pcap).CombinedOutput(); err != nil {
		t.Fatalf("text2pcap: %v (%s)", err, out)
	}
	out, err := exec.Command("tshark", "-r", pcap, "-V").CombinedOutput()
	if err != nil {
		t.Fatalf("tshark: %v (%s)", err, out)
	}
	return string(out)
}

// assertDissection asserts zero-malformed dissection plus every expected
// substring (semantic field spot checks).
func assertDissection(t *testing.T, name string, lppPDU []byte, expect []string) {
	t.Helper()
	out := dissect(t, lppPDU)
	lower := strings.ToLower(out)
	for _, bad := range []string{"malformed", "dissector bug", "[expert info (error"} {
		if strings.Contains(lower, bad) {
			t.Fatalf("%s (%s): tshark flagged %q:\n%s", name, hex.EncodeToString(lppPDU), bad, out)
		}
	}
	if !strings.Contains(out, "LTE Positioning Protocol (LPP)") {
		t.Fatalf("%s: dissection never reached the LPP dissector:\n%s", name, out)
	}
	for _, want := range expect {
		if !strings.Contains(out, want) {
			t.Errorf("%s: dissection missing %q", name, want)
		}
	}
	if t.Failed() {
		t.Logf("full dissection for %s:\n%s", name, out)
	}
}

// TestTsharkOracle_AllGoldenPDUs is the LMF-009 hard gate: zero malformed
// ASN.1 across all golden PDUs under the tshark 4.6.4 LPP dissector, with
// per-field spot checks (transaction number, gnss-id, coordinates, codePhase).
func TestTsharkOracle_AllGoldenPDUs(t *testing.T) {
	requireTools(t)

	t.Run("RequestCapabilities", func(t *testing.T) {
		b, err := BuildRequestCapabilities(goldenTxn1)
		if err != nil {
			t.Fatal(err)
		}
		assertDissection(t, "RequestCapabilities", b, []string{
			"initiator: locationServer (0)",
			"transactionNumber: 1",
			"endTransaction: False",
			"c1: requestCapabilities (0)",
			"gnss-SupportListReq: True",
			"assistanceDataSupportListReq: False",
		})
	})

	t.Run("ProvideCapabilitiesGPS", func(t *testing.T) {
		b, err := BuildProvideCapabilities(goldenTxn1, true)
		if err != nil {
			t.Fatal(err)
		}
		assertDissection(t, "ProvideCapabilities(gps)", b, []string{
			"transactionNumber: 1",
			"endTransaction: True",
			"c1: provideCapabilities (1)",
			"gnss-id: gps (0)",
			"posModes: 20 [bit length 8, 0010 0000",       // ue-assisted only
			"gnss-SignalIDs: 80 [bit length 8, 1000 0000", // GPS L1 C/A
			"adr-Support: False",
			"velocityMeasurementSupport: False",
		})
	})

	t.Run("ProvideCapabilitiesNone", func(t *testing.T) {
		b, err := BuildProvideCapabilities(goldenTxn1, false)
		if err != nil {
			t.Fatal(err)
		}
		assertDissection(t, "ProvideCapabilities(none)", b, []string{
			"c1: provideCapabilities (1)",
		})
	})

	t.Run("ProvideAssistanceData", func(t *testing.T) {
		b, err := BuildProvideAssistanceData(goldenTxn2, goldenAssistanceData())
		if err != nil {
			t.Fatal(err)
		}
		assertDissection(t, "ProvideAssistanceData", b, []string{
			"transactionNumber: 2",
			"endTransaction: True",
			"c1: provideAssistanceData (3)",
			"gnss-id: gps (0)",
			"gnss-DayNumber: 16616",
			"gnss-TimeOfDay: 41618",
			"referenceTimeUnc: 32.607413us (32)", // r = 0.5·(1.14^K − 1) µs confirmed
			"degreesLatitude: 40.416796 degrees (3767118)",
			"degreesLongitude: -3.703809 degrees (-172610)", // floor toward −∞ confirmed
			"altitudeDirection: height (0)",
			"confidence: 68%",
		})
	})

	t.Run("RequestLocationInformation", func(t *testing.T) {
		b, err := BuildRequestLocationInformation(goldenTxn3)
		if err != nil {
			t.Fatal(err)
		}
		assertDissection(t, "RequestLocationInformation", b, []string{
			"transactionNumber: 3",
			"endTransaction: False",
			"c1: requestLocationInformation (4)",
			"locationInformationType: locationMeasurementsRequired (1)",
			"gnss-ids: 80 [bit length 8, 1000 0000", // gps
		})
	})

	t.Run("ProvideLocationInformation", func(t *testing.T) {
		b, err := BuildProvideLocationInformation(goldenTxn3, goldenMeasurements(t))
		if err != nil {
			t.Fatal(err)
		}
		assertDissection(t, "ProvideLocationInformation", b, []string{
			"transactionNumber: 3",
			"endTransaction: True",
			"c1: provideLocationInformation (5)",
			"gnss-TOD-msec: 2018250ms",
			"satellite-id: 0",
			"satellite-id: 3",
			"cNo: 44 dB-Hz",
			"mpathDet: low (1)",
			"codePhase: 0.384101ms (805518)", // SV 0: 805518/2^21 ms
			"integerCodePhase: 73ms",
			"integerCodePhase: 78ms",
			"codePhaseRMSError: 2.000000 <= P < 2.000000 (20)", // k=20 (see file header)
		})
	})

	t.Run("ProvideLocationInformationError", func(t *testing.T) {
		b, err := BuildProvideLocationInformationError(goldenTxn3, GNSSErrorAssistanceDataMissing)
		if err != nil {
			t.Fatal(err)
		}
		assertDissection(t, "ProvideLocationInformation(error)", b, []string{
			"transactionNumber: 3",
			"gnss-Error: targetDeviceErrorCauses (1)",
			"cause: assistanceDataMissing (2)",
		})
	})
}
