package roaming

import "testing"

// ROAM-002: optional home_nfs.smf_api_root, full DNN, H-SMF URI.
// Ref: TS 23.003 §9.1.2; TS 29.502 Table 6.1.6.2.2-1.

const hrRoots = "      ausf_api_root: https://ausf.5gc.mnc002.mcc001.3gppnetwork.org:8002\n      udm_api_root: https://udm.5gc.mnc002.mcc001.3gppnetwork.org:8003\n"

func TestPartnersSMFAPIRoot(t *testing.T) {
	hdr := "partners:\n  - plmn: {mcc: \"001\", mnc: \"02\"}\n    home_nfs:\n" + hrRoots
	cases := []struct {
		name, extra, want string
		wantErr           bool
	}{
		{"absent", "", "", false},
		{"valid", "      smf_api_root: https://smf.5gc.mnc002.mcc001.3gppnetwork.org:8004\n", "https://smf.5gc.mnc002.mcc001.3gppnetwork.org:8004", false},
		{"http", "      smf_api_root: http://smf.5gc.mnc002.mcc001.3gppnetwork.org:8004\n", "", true},
		{"plmn mismatch", "      smf_api_root: https://smf.5gc.mnc003.mcc001.3gppnetwork.org:8004\n", "", true},
		{"with path", "      smf_api_root: https://smf.5gc.mnc002.mcc001.3gppnetwork.org:8004/x\n", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := LoadPartners(writeFile(t, hdr+tc.extra), nil)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want error")
				}
				return
			}
			if err != nil || len(got) != 1 || got[0].SMFAPIRoot != tc.want {
				t.Fatalf("got %+v err %v want smf %q", got, err, tc.want)
			}
		})
	}
}

func TestInlineSMFAPIRootValidatedAndRouted(t *testing.T) {
	mk := func(smf string) Config {
		return Config{Enabled: true, SEPPAddress: "sepp:8443", HomePLMNs: []HomePLMN{{
			PLMN:        PLMN{"001", "02"},
			AUSFAPIRoot: "https://ausf.5gc.mnc002.mcc001.3gppnetwork.org:8002",
			UDMAPIRoot:  "https://udm.5gc.mnc002.mcc001.3gppnetwork.org:8003",
			SMFAPIRoot:  smf,
		}}}
	}
	if _, err := New(mk("http://bad"), "001", "01"); err == nil {
		t.Fatal("invalid inline smf_api_root must fail")
	}
	r, err := New(mk("https://smf.5gc.mnc002.mcc001.3gppnetwork.org:8004"), "001", "01")
	if err != nil {
		t.Fatal(err)
	}
	route, err := r.Classify("imsi-001020000000001")
	if err != nil || route == nil {
		t.Fatalf("classify: %v %v", route, err)
	}
	if got := route.HSMFURI(); got != "https://smf.5gc.mnc002.mcc001.3gppnetwork.org:8004/nsmf-pdusession/v1" {
		t.Errorf("HSMFURI = %q", got)
	}
	r2, _ := New(mk(""), "001", "01")
	route2, _ := r2.Classify("imsi-001020000000001")
	if _, ok := route2.NewHomeRouting("internet", 1, "000001"); ok || route2.HSMFURI() != "" {
		t.Error("route without smf_api_root must not yield home routing")
	}
}

func TestFullDNN(t *testing.T) {
	for _, tc := range []struct {
		dnn string
		p   PLMN
		w   string
	}{
		{"internet", PLMN{"001", "02"}, "internet.mnc002.mcc001.gprs"},
		{"ims", PLMN{"310", "260"}, "ims.mnc260.mcc310.gprs"},
	} {
		if got := FullDNN(tc.dnn, tc.p); got != tc.w {
			t.Errorf("FullDNN = %q want %q", got, tc.w)
		}
	}
}
