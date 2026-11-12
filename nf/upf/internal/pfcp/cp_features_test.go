package pfcp

// cp_features_test.go — the UPF parses, stores and logs the CP Function
// Features of the SMF (peer) and adds nothing to its responses.
// Ref: TS 29.244 §6.2.6, §8.2.58.

import (
	"bytes"
	"testing"
	"time"

	pfcpie "github.com/wmnsk/go-pfcp/ie"
	pfcpmsg "github.com/wmnsk/go-pfcp/message"
)

func TestCPFeaturesStoredAndResponseUnchanged(t *testing.T) {
	srv, _, addr, stop := startTestUPF(t)
	defer stop()
	rts := time.Now().UTC().Truncate(time.Second)
	node := pfcpie.NewNodeID("", "", "smf")

	send := func(seq uint32, feat *pfcpie.IE) {
		ies := []*pfcpie.IE{node, pfcpie.NewRecoveryTimeStamp(rts)}
		if feat != nil {
			ies = append(ies, feat)
		}
		r, ok := sendAndRecv(t, addr, pfcpmsg.NewAssociationSetupRequest(seq, ies...)).(*pfcpmsg.AssociationSetupResponse)
		if !ok {
			t.Fatal("expected AssociationSetupResponse")
		}
		if c, err := r.Cause.Cause(); err != nil || c != pfcpie.CauseRequestAccepted {
			t.Fatalf("cause = %v, %v", c, err)
		}
		if r.NodeID == nil || r.RecoveryTimeStamp == nil {
			t.Fatal("response lacks NodeID or RTS")
		}
		if r.UPFunctionFeatures != nil || r.CPFunctionFeatures != nil || len(r.IEs) != 0 ||
			len(r.UserPlaneIPResourceInformation) != 0 || r.PFCPASRspFlags != nil || r.UPFInstanceID != nil {
			t.Fatalf("response IEs not exactly NodeID+Cause+RTS (extra: %d unparsed)", len(r.IEs))
		}
	}

	// 1 octet.
	send(1, pfcpie.New(pfcpie.CPFunctionFeatures, []byte{0x01}))
	if got := srv.cpPeerFeaturesFor("smf"); !bytes.Equal(got.Raw, []byte{0x01}) || len(got.Names) != 1 {
		t.Fatalf("1-octet: %+v", got)
	}
	// 4 octets with bits beyond the table: raw preserved, names decoded.
	ext := []byte{0x03, 0x01, 0xAA, 0xFF}
	send(2, pfcpie.New(pfcpie.CPFunctionFeatures, ext))
	got := srv.cpPeerFeaturesFor("smf")
	if !bytes.Equal(got.Raw, ext) || len(got.Names) == 0 {
		t.Fatalf("extended: %+v", got)
	}
	// Absent IE replaces with empty; no error.
	send(3, nil)
	if got := srv.cpPeerFeaturesFor("smf"); len(got.Raw) != 0 || len(got.Names) != 0 {
		t.Fatalf("absent: %+v", got)
	}
}

func TestRecordCPFeaturesNotAliased(t *testing.T) {
	srv, _, _, stop := startTestUPF(t)
	defer stop()
	buf := []byte{0x03, 0x01, 0xAA, 0xFF}
	srv.recordCPFeatures("smf", pfcpie.New(pfcpie.CPFunctionFeatures, buf))
	for i := range buf {
		buf[i] = 0
	}
	if got := srv.cpPeerFeaturesFor("smf"); !bytes.Equal(got.Raw, []byte{0x03, 0x01, 0xAA, 0xFF}) {
		t.Fatalf("stored value aliased the receive buffer: % x", got.Raw)
	}
}
