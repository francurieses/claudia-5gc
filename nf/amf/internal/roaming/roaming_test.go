package roaming

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func testCfg() Config {
	return Config{
		Enabled:     true,
		SEPPAddress: "sepp:8014",
		HomePLMNs: []HomePLMN{{
			PLMN:        PLMN{MCC: "001", MNC: "02"},
			AUSFAPIRoot: "https://ausf.5gc.mnc002.mcc001.3gppnetwork.org:8002",
			UDMAPIRoot:  "https://udm.5gc.mnc002.mcc001.3gppnetwork.org:8003",
		}},
	}
}

func TestNewDisabledIsNilRouter(t *testing.T) {
	for _, c := range []Config{{}, {Enabled: false, SEPPAddress: "x"}} {
		r, err := New(c, "001", "01")
		if r != nil || err != nil {
			t.Fatalf("New(%+v) = %v, %v; want nil, nil", c, r, err)
		}
		if r.Enabled() {
			t.Fatal("nil router must not be enabled")
		}
		if rt, err := r.Classify("suci-0-001-02-0-0-0-1"); rt != nil || err != nil {
			t.Fatalf("nil router Classify = %v, %v", rt, err)
		}
	}
}

func TestNewValidation(t *testing.T) {
	mut := func(f func(*Config)) Config { c := testCfg(); f(&c); return c }
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{"ok", testCfg(), ""},
		{"sepp without port", mut(func(c *Config) { c.SEPPAddress = "sepp" }), "sepp_address"},
		{"ausf http", mut(func(c *Config) { c.HomePLMNs[0].AUSFAPIRoot = "http://ausf.5gc.mnc002.mcc001.3gppnetwork.org:8002" }), "https"},
		{"udm no fqdn labels", mut(func(c *Config) { c.HomePLMNs[0].UDMAPIRoot = "https://udm:8003" }), "FQDN"},
		{"ausf labels of other plmn", mut(func(c *Config) { c.HomePLMNs[0].AUSFAPIRoot = "https://ausf.5gc.mnc003.mcc001.3gppnetwork.org:8002" }), "mnc002"},
		{"bad mnc", mut(func(c *Config) { c.HomePLMNs[0].PLMN.MNC = "2" }), "invalid plmn"},
		{"duplicate", mut(func(c *Config) { c.HomePLMNs = append(c.HomePLMNs, c.HomePLMNs[0]) }), "duplicate"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg, "001", "01")
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	r, err := New(testCfg(), "001", "01")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		identity string
		roaming  bool
		notConf  bool
	}{
		{"serving suci", "suci-0-001-01-0-0-0-0000000001", false, false},
		{"home suci", "suci-0-001-02-0-0-0-0000000001", true, false},
		{"profile A suci", "suci-0-001-02-0000-1-1-abcdef", true, false},
		{"unconfigured suci", "suci-0-001-03-0-0-0-0000000001", false, true},
		{"serving supi", "imsi-001010000000001", false, false},
		{"home supi", "imsi-001020000000001", true, false},
		{"unconfigured supi", "imsi-001030000000001", false, true},
		{"guti stays local", "guti-00101010000abcdef", false, false},
		{"unknown stays local", "unknown", false, false},
		{"garbage suci stays local", "suci-x", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rt, err := r.Classify(tc.identity)
			if tc.notConf {
				if !errors.Is(err, ErrHomePLMNNotConfigured) || rt != nil {
					t.Fatalf("got %v, %v; want ErrHomePLMNNotConfigured", rt, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (rt != nil) != tc.roaming {
				t.Fatalf("route = %v, roaming want %v", rt, tc.roaming)
			}
			if rt != nil {
				if rt.ViaSEPP != "sepp:8014" || rt.HomePLMN.String() != "001-02" {
					t.Fatalf("route %+v", rt)
				}
				if h := rt.Hop(NFAUSF); h.APIRoot != "https://ausf.5gc.mnc002.mcc001.3gppnetwork.org:8002" ||
					h.URL("/p") != "https://sepp:8014/p" {
					t.Fatalf("ausf hop %+v", h)
				}
				if h := rt.Hop(NFUDM); h.APIRoot != "https://udm.5gc.mnc002.mcc001.3gppnetwork.org:8003" {
					t.Fatalf("udm hop %+v", h)
				}
			}
		})
	}
}

func TestRegistryAndContext(t *testing.T) {
	r, _ := New(testCfg(), "001", "01")
	rt, _ := r.Classify("suci-0-001-02-0-0-0-1")
	r.Remember("imsi-001020000000001", rt)
	if r.ForSUPI("imsi-001020000000001") != rt {
		t.Fatal("route not remembered")
	}
	r.Forget("imsi-001020000000001")
	if r.ForSUPI("imsi-001020000000001") != nil {
		t.Fatal("route not forgotten")
	}
	if RouteFrom(context.Background()) != nil {
		t.Fatal("empty ctx must have no route")
	}
	if RouteFrom(WithRoute(context.Background(), rt)) != rt {
		t.Fatal("ctx route lost")
	}
	if ctx := context.Background(); WithRoute(ctx, nil) != ctx {
		t.Fatal("nil route must not wrap ctx")
	}
}

func TestRememberNilDeletesAndIsBounded(t *testing.T) {
	r, _ := New(testCfg(), "001", "01")
	rt, _ := r.Classify("suci-0-001-02-0-0-0-1")
	r.Remember("imsi-001020000000001", rt)
	r.Remember("imsi-001020000000001", nil) // re-registered as non-roaming
	if r.ForSUPI("imsi-001020000000001") != nil {
		t.Fatal("Remember(nil) must delete the entry")
	}
	for i := 0; i < MaxRememberedRoutes; i++ {
		if !r.Remember(fmt.Sprintf("imsi-%d", i), rt) {
			t.Fatalf("entry %d refused below the bound", i)
		}
	}
	if r.Remember("imsi-overflow", rt) || r.ForSUPI("imsi-overflow") != nil {
		t.Fatal("entry beyond the bound must be refused")
	}
	if !r.Remember("imsi-1", rt) {
		t.Fatal("updating an existing entry must be allowed when full")
	}
}

func TestClassifyNonNullSchemeAndUnclassifiable(t *testing.T) {
	r, _ := New(testCfg(), "001", "01")
	// Profile A (scheme 1): the home network identifier is still in clear.
	rt, err := r.Classify("suci-0-001-02-0-1-1-0a0b0c")
	if err != nil || rt == nil || rt.HomePLMN.String() != "001-02" || rt.ServingPLMN.String() != "001-01" {
		t.Fatalf("profile A SUCI: %+v %v", rt, err)
	}
	for _, id := range []string{"5g-guti-00101ca0100000001", "suci-bogus", "suci-1-example.com-0", ""} {
		if r.Classifiable(id) {
			t.Errorf("%q must not be classifiable", id)
		}
	}
	if !r.Classifiable("suci-0-001-02-0-1-1-0a") || !r.Classifiable("imsi-001020000000001") {
		t.Error("SUCI/IMSI must be classifiable")
	}
}

func TestOwnsSUPIAndOriginatingID(t *testing.T) {
	r, _ := New(testCfg(), "001", "01")
	rt, _ := r.Classify("suci-0-001-02-0-0-0-1")
	if !rt.OwnsSUPI("imsi-001020000000001") || rt.OwnsSUPI("imsi-001010000000001") || rt.OwnsSUPI("nai-x@y") {
		t.Fatal("OwnsSUPI")
	}
	if got := rt.Hop(NFUDM).OriginatingNetworkID(); got != "001-01" {
		t.Fatalf("originating network id %q", got)
	}
	if (Hop{}).OriginatingNetworkID() != "" {
		t.Fatal("unknown serving PLMN must give no header")
	}
}
