package n32c

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// PORTAL-UI-22: outcomes are recorded per partner PLMN and role, the context
// gauge follows the production store, and non-partners never get a label.
func TestActivityAndMetrics(t *testing.T) {
	ts, remote := peerServer(t, "rel19")
	f := newFixture(t, "rel19", func(c *Config) { c.HTTPClient = ts.Client() })

	// remote uses the production store: its partner gauge starts at 0, not absent.
	gauge := n32cContextEstablished.WithLabelValues(plmnLocal.String())
	if v := testutil.ToFloat64(gauge); v != 0 {
		t.Fatalf("gauge before handshake = %v, want 0", v)
	}
	okInit := n32cHandshakeTotal.WithLabelValues(plmn1.String(), RoleInitiator, resultOK)
	before := testutil.ToFloat64(okInit)

	if _, err := f.svc.Exchange(context.Background(), ts.URL, plmn1); err != nil {
		t.Fatal(err)
	}
	if got := testutil.ToFloat64(okInit) - before; got != 1 {
		t.Fatalf("initiator OK counter delta = %v, want 1", got)
	}
	if a, ok := f.svc.LastAttempt(plmn1); !ok || a.Role != RoleInitiator || a.Result != resultOK {
		t.Fatalf("initiator last attempt = %+v %v", a, ok)
	}
	if a, ok := remote.LastAttempt(plmnLocal); !ok || a.Role != RoleResponder || a.Result != resultOK {
		t.Fatalf("responder last attempt = %+v %v", a, ok)
	}
	if v := testutil.ToFloat64(gauge); v != 1 {
		t.Fatalf("gauge after handshake = %v, want 1", v)
	}

	if err := f.svc.Teardown(context.Background(), ts.URL, plmn1); err != nil {
		t.Fatal(err)
	}
	if v := testutil.ToFloat64(gauge); v != 0 {
		t.Fatalf("gauge after teardown = %v, want 0", v)
	}
	if a, _ := f.svc.LastAttempt(plmn1); a.Cause != "teardown" {
		t.Fatalf("last attempt after teardown = %+v", a)
	}
}

func TestActivityRejectAttribution(t *testing.T) {
	f := newFixture(t, "rel17")
	// Partner rejected (PRINS only): attributed to the partner PLMN.
	w := f.send(t, peer1FQDN, `{"sender":"`+peer1FQDN+`","supportedSecCapabilityList":["PRINS"]}`)
	if w.Code != 403 {
		t.Fatalf("status %d", w.Code)
	}
	if a, ok := f.svc.LastAttempt(plmn1); !ok || a.Result != resultReject || a.Role != RoleResponder {
		t.Fatalf("partner reject not recorded: %+v %v", a, ok)
	}
	// Non-partner: counted under "other", never stored.
	other := n32cHandshakeTotal.WithLabelValues(peerLabelOther, RoleResponder, resultReject)
	before := testutil.ToFloat64(other)
	np := "sepp.5gc.mnc099.mcc999.3gppnetwork.org"
	f.send(t, np, `{"sender":"`+np+`","supportedSecCapabilityList":["TLS"]}`)
	if testutil.ToFloat64(other)-before != 1 {
		t.Fatal("non-partner reject not counted under peer_plmn=other")
	}
	if _, ok := f.svc.LastAttempt(PlmnId{"999", "99"}); ok {
		t.Fatal("non-partner must not be stored")
	}
}

func TestStoreSnapshotOrdered(t *testing.T) {
	st := NewStore(nil)
	st.Replace(Context{RemotePLMN: plmn3})
	st.Replace(Context{RemotePLMN: plmn1})
	got := st.Snapshot()
	if len(got) != 2 || got[0].RemotePLMN.Key() != plmn1.Key() || got[1].RemotePLMN.Key() != plmn3.Key() {
		t.Fatalf("snapshot = %+v", got)
	}
}
