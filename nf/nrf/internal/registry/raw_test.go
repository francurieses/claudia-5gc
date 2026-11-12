package registry

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"reflect"
	"testing"
	"time"
)

// legacyProfile is a copy of the pre-REL19-2.5 NFProfile definition, used to
// prove that profiles without raw encode byte-identically.
type legacyProfile struct {
	NFInstanceID   string          `json:"nfInstanceId"`
	NFType         NFType          `json:"nfType"`
	NFStatus       NFStatus        `json:"nfStatus"`
	HeartBeatTimer int             `json:"heartBeatTimer,omitempty"`
	PLMNList       []PLMN          `json:"plmnList,omitempty"`
	SNSSAIs        []SNSSAI        `json:"sNssais,omitempty"`
	NSIList        []string        `json:"nsiList,omitempty"`
	FQDN           string          `json:"fqdn,omitempty"`
	IPv4Addresses  []string        `json:"ipv4Addresses,omitempty"`
	NFServices     []legacyService `json:"nfServices,omitempty"`
	DNNList        []string        `json:"dnnList,omitempty"`
	Capacity       int             `json:"capacity,omitempty"`
	Priority       int             `json:"priority,omitempty"`
}

type legacyService struct {
	ServiceInstanceID string             `json:"serviceInstanceId"`
	ServiceName       string             `json:"serviceName"`
	Versions          []NFServiceVersion `json:"versions"`
	Scheme            string             `json:"scheme"`
	NFServiceStatus   string             `json:"nfServiceStatus"`
	FQDN              string             `json:"fqdn,omitempty"`
	IPEndpoints       []IPEndpoint       `json:"ipEndPoints,omitempty"`
	APIPrefix         string             `json:"apiPrefix,omitempty"`
}

func TestMarshalNoRawByteIdenticalToLegacy(t *testing.T) {
	vers := []NFServiceVersion{{APIVersionInURI: "v1", APIFullVersion: "1.0.0"}}
	p := &NFProfile{
		NFInstanceID: "id1", NFType: NFTypeSMF, NFStatus: NFStatusRegistered, HeartBeatTimer: 60,
		PLMNList: []PLMN{{MCC: "001", MNC: "01"}}, SNSSAIs: []SNSSAI{{SST: 1, SD: "000001"}},
		NSIList: []string{"a"}, FQDN: "smf.example", IPv4Addresses: []string{"10.0.0.1"},
		DNNList: []string{"internet"}, Capacity: 10, Priority: 2,
		NFServices: []NFService{{ServiceInstanceID: "s", ServiceName: "nsmf-pdusession", Versions: vers,
			Scheme: "https", NFServiceStatus: "REGISTERED", FQDN: "f", APIPrefix: "/p",
			IPEndpoints: []IPEndpoint{{IPv4Address: "10.0.0.1", Port: 80}}}},
		registeredAt: time.Now(), lastSeen: time.Now(),
	}
	l := &legacyProfile{
		NFInstanceID: p.NFInstanceID, NFType: p.NFType, NFStatus: p.NFStatus, HeartBeatTimer: 60,
		PLMNList: p.PLMNList, SNSSAIs: p.SNSSAIs, NSIList: p.NSIList, FQDN: p.FQDN,
		IPv4Addresses: p.IPv4Addresses, DNNList: p.DNNList, Capacity: 10, Priority: 2,
		NFServices: []legacyService{{ServiceInstanceID: "s", ServiceName: "nsmf-pdusession", Versions: vers,
			Scheme: "https", NFServiceStatus: "REGISTERED", FQDN: "f", APIPrefix: "/p",
			IPEndpoints: []IPEndpoint{{IPv4Address: "10.0.0.1", Port: 80}}}},
	}
	got, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(l)
	if string(got) != string(want) {
		t.Errorf("not byte-identical\n got: %s\nwant: %s", got, want)
	}
}

const rawJSON = `{"nfInstanceId":"id1","nfType":"SMF","nfStatus":"REGISTERED","smfInfo":{"a":[1,2]},"fooRel19Attr":"x","nfServices":[{"serviceInstanceId":"s","serviceName":"nsmf-pdusession","allowedPlmns":[{"mcc":"001"}],"ipEndPoints":[{"port":1,"transport":"TCP"}]}]}`

func anyOf(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return v
}

func TestRedisRoundTripRaw(t *testing.T) {
	var p NFProfile
	if err := json.Unmarshal([]byte(rawJSON), &p); err != nil {
		t.Fatal(err)
	}
	p.HeartBeatTimer = DefaultHeartbeatTimer // NRF-side mutation
	orig, err := json.Marshal(&p)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := encodeProfile(&p)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := decodeProfile(enc)
	if err != nil {
		t.Fatal(err)
	}
	again, err := json.Marshal(dec)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(anyOf(t, orig), anyOf(t, again)) {
		t.Errorf("round trip differs\n orig: %s\nagain: %s", orig, again)
	}
	m := anyOf(t, again).(map[string]any)
	if m["fooRel19Attr"] != "x" || m["smfInfo"] == nil || m["heartBeatTimer"] != float64(DefaultHeartbeatTimer) {
		t.Errorf("attributes lost: %s", again)
	}

	t.Run("live redis", func(t *testing.T) {
		addr := os.Getenv("NRF_TEST_REDIS_ADDR")
		if addr == "" {
			t.Skip("NRF_TEST_REDIS_ADDR not set")
		}
		r, err := NewRedis(addr, time.Minute, newLogger())
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		var q NFProfile
		if err := json.Unmarshal([]byte(rawJSON), &q); err != nil {
			t.Fatal(err)
		}
		q.NFInstanceID = "raw-roundtrip-test"
		if err := r.Register(&q); err != nil {
			t.Fatal(err)
		}
		defer r.Deregister(q.NFInstanceID)
		got, ok := r.Get(q.NFInstanceID)
		if !ok {
			t.Fatal("get failed")
		}
		b, _ := json.Marshal(got)
		if anyOf(t, b).(map[string]any)["fooRel19Attr"] != "x" {
			t.Errorf("Get lost raw: %s", b)
		}
		found := false
		for _, d := range r.Discover(DiscoveryFilter{TargetNFType: NFTypeSMF}) {
			if d.NFInstanceID == q.NFInstanceID {
				db, _ := json.Marshal(d)
				found = anyOf(t, db).(map[string]any)["fooRel19Attr"] == "x"
			}
		}
		if !found {
			t.Error("Discover lost raw")
		}
	})
}

func TestNFTypeConstants(t *testing.T) {
	if NFTypeSEPP != "SEPP" || NFTypeMBSMF != "MB_SMF" || NFType5GEIR != "5G_EIR" || NFTypeAIOTF != "AIOTF" {
		t.Error("NFType constants wrong")
	}
}

func newLogger() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }
