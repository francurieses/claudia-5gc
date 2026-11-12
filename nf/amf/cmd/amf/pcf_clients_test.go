// pcf_clients_test.go - unit tests for the AMF Npcf consumers (AM and UE
// policy association): polAssoId from the Location header (TS 29.501 §4.4.1,
// TS 29.507 §5.6.2.2, TS 29.525 §5.6.2.2), uePolicy container, legacy-body
// fallback and DELETE status handling.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

func pcfTLSServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv, strings.TrimPrefix(srv.URL, "https://")
}

func TestPolicyAssociationID(t *testing.T) {
	const am = "/npcf-am-policy-control/v1/policies"
	tests := []struct {
		name, loc, body, want string
		wantErr               bool
	}{
		{"absolute", "https://pcf:8006" + am + "/a1", "", "a1", false},
		{"relative", am + "/a2", "", "a2", false},
		{"trailing slash", "https://pcf:8006" + am + "/a3/", "", "a3", false},
		{"location wins over body", "https://pcf" + am + "/a4", "legacy", "a4", false},
		{"legacy body when no location", "", "legacy", "legacy", false},
		{"neither", "", "", "", true},
		{"garbage location, no fallback", "http://[::1", "legacy", "", true},
		{"host-only location", "https://pcf:8006", "", "", true},
		{"wrong collection", "https://pcf:8006/npcf-ue-policy-control/v1/policies/a5", "legacy", "", true},
		{"extra segments", "https://pcf:8006" + am + "/a6/x", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := policyAssociationID(tt.loc, am, tt.body)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Errorf("policyAssociationID(%q,%q) = %q, %v; want %q (err=%v)", tt.loc, tt.body, got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestCreateUEPolicyAssociation(t *testing.T) {
	container := []byte{0x01, 0x02, 0x03, 0xAA}
	b64 := base64.StdEncoding.EncodeToString(container)

	tests := []struct {
		name     string
		location string
		body     string
		wantID   string
		wantErr  bool
	}{
		{"new format: uePolicy + absolute Location", "ABS:/npcf-ue-policy-control/v1/policies/ue-1",
			`{"suppFeat":"0","uePolicy":"` + b64 + `"}`, "ue-1", false},
		{"legacy format: uePolicySections + polAssoId, no Location", "",
			`{"polAssoId":"ue-2","uePolicySections":{"s1":{"uePolicySectionContent":"` + b64 + `"}}}`, "ue-2", false},
		{"no id anywhere", "", `{"uePolicy":"` + b64 + `"}`, "", true},
		{"Location under the AM collection", "ABS:/npcf-am-policy-control/v1/policies/x", `{"uePolicy":"` + b64 + `"}`, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, addr := pcfTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/npcf-ue-policy-control/v1/policies" {
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
				}
				if loc, ok := strings.CutPrefix(tt.location, "ABS:"); ok {
					w.Header().Set("Location", "https://"+r.Host+loc)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(tt.body))
			})
			c := &HTTPPCFClient{address: addr, client: srv.Client()}
			id, got, err := c.CreateUEPolicyAssociation(context.Background(), "imsi-001010000000001", "00101")
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if id != tt.wantID {
				t.Errorf("polAssoId = %q, want %q", id, tt.wantID)
			}
			if !bytes.Equal(got, container) {
				t.Errorf("container = %x, want %x", got, container)
			}
		})
	}
}

func TestCreateAMPolicyAssociation(t *testing.T) {
	tests := []struct {
		name     string
		location string
		body     string
		wantID   string
		wantErr  bool
	}{
		{"new format: absolute Location, no polAssoId", "ABS:/npcf-am-policy-control/v1/policies/am-1",
			`{"rfsp":7}`, "am-1", false},
		{"legacy format: polAssoId, no Location", "", `{"polAssoId":"am-2","rfsp":7}`, "am-2", false},
		{"no id anywhere", "", `{"rfsp":7}`, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, addr := pcfTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
				if loc, ok := strings.CutPrefix(tt.location, "ABS:"); ok {
					w.Header().Set("Location", "https://"+r.Host+loc)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(tt.body))
			})
			c := &HTTPAMPolicyClient{address: addr, client: srv.Client()}
			id, rfsp, _, err := c.CreateAMPolicyAssociation(context.Background(), "imsi-001010000000001", "3GPP_ACCESS", "001", "01")
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if id != tt.wantID || rfsp != 7 {
				t.Errorf("got id=%q rfsp=%d, want id=%q rfsp=7", id, rfsp, tt.wantID)
			}
		})
	}
}

func TestDeletePolicyAssociations(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		wantErr     bool
		wantMsg     string
		wantInfoLog bool
	}{
		{name: "204 success", status: http.StatusNoContent},
		{"404 problem+json already gone", http.StatusNotFound, "application/problem+json", `{"cause":"CONTEXT_NOT_FOUND"}`, false, "", true},
		{"404 problem+json with charset", http.StatusNotFound, "application/problem+json; charset=utf-8", `{"cause":"USER_UNKNOWN"}`, false, "", true},
		{"404 problem+json without cause", http.StatusNotFound, "application/problem+json", `{}`, false, "", true},
		{"404 text/plain (mux) is an error", http.StatusNotFound, "text/plain; charset=utf-8", "404 page not found\n", true, "status 404", false},
		{"404 no content type is an error", http.StatusNotFound, "", "", true, "status 404", false},
		{"404 application/json is an error", http.StatusNotFound, "application/json", `{"cause":"X"}`, true, "status 404", false},
		{"500 with cause", http.StatusInternalServerError, "application/problem+json", `{"cause":"SYSTEM_FAILURE"}`, true, "SYSTEM_FAILURE", false},
		{"400", http.StatusBadRequest, "application/problem+json", `{"cause":"MANDATORY_IE_MISSING"}`, true, "status 400", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPaths []string
			srv, addr := pcfTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Errorf("method = %s, want DELETE", r.Method)
				}
				gotPaths = append(gotPaths, r.URL.Path)
				if tt.contentType != "" {
					w.Header().Set("Content-Type", tt.contentType)
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
			var logBuf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&logBuf, nil)))
			t.Cleanup(func() { slog.SetDefault(prev) })

			ue := &HTTPPCFClient{address: addr, client: srv.Client()}
			am := &HTTPAMPolicyClient{address: addr, client: srv.Client()}
			for name, err := range map[string]error{
				"ue": ue.DeleteUEPolicyAssociation(context.Background(), "p1"),
				"am": am.DeleteAMPolicyAssociation(context.Background(), "p1"),
			} {
				if (err != nil) != tt.wantErr {
					t.Errorf("%s: err = %v, wantErr %v", name, err, tt.wantErr)
				}
				if err != nil && !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("%s: error %q lacks %q", name, err, tt.wantMsg)
				}
			}
			sort.Strings(gotPaths)
			if len(gotPaths) != 2 || gotPaths[0] != "/npcf-am-policy-control/v1/policies/p1" || gotPaths[1] != "/npcf-ue-policy-control/v1/policies/p1" {
				t.Errorf("paths = %v, want one UE and one AM request", gotPaths)
			}
			out := logBuf.String()
			if tt.wantInfoLog {
				for _, want := range []string{`"level":"INFO"`, `"interface":"N15"`, `"direction":"IN"`, `"result":"OK"`, `"pol_asso_id":"p1"`, `"spec_ref"`, `"cause"`} {
					if !strings.Contains(out, want) {
						t.Errorf("already-gone log lacks %s: %s", want, out)
					}
				}
			} else if strings.Contains(out, "already released") {
				t.Errorf("unexpected already-gone log: %s", out)
			}
		})
	}
}

func TestDeletePolicyAssociationEmptyID(t *testing.T) {
	calls := 0
	srv, addr := pcfTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	})
	if err := (&HTTPPCFClient{address: addr, client: srv.Client()}).DeleteUEPolicyAssociation(context.Background(), ""); err == nil {
		t.Error("UE: empty id must be an error")
	}
	if err := (&HTTPAMPolicyClient{address: addr, client: srv.Client()}).DeleteAMPolicyAssociation(context.Background(), ""); err == nil {
		t.Error("AM: empty id must be an error")
	}
	if calls != 0 {
		t.Errorf("empty id sent %d request(s); want none", calls)
	}
}

func TestPolicyClientsRequestBuildError(t *testing.T) {
	// A control character in the address makes http.NewRequestWithContext fail.
	bad := "pcf\x7f:1"
	ctx := context.Background()
	if _, _, err := (&HTTPPCFClient{address: bad, client: http.DefaultClient}).CreateUEPolicyAssociation(ctx, "s", "p"); err == nil {
		t.Error("UE create: build error swallowed")
	}
	if _, _, _, err := (&HTTPAMPolicyClient{address: bad, client: http.DefaultClient}).CreateAMPolicyAssociation(ctx, "s", "a", "001", "01"); err == nil {
		t.Error("AM create: build error swallowed")
	}
	if err := (&HTTPPCFClient{address: bad, client: http.DefaultClient}).DeleteUEPolicyAssociation(ctx, "p1"); err == nil {
		t.Error("UE delete: build error swallowed")
	}
	if err := (&HTTPAMPolicyClient{address: bad, client: http.DefaultClient}).DeleteAMPolicyAssociation(ctx, "p1"); err == nil {
		t.Error("AM delete: build error swallowed")
	}
}

func TestDeletePolicyAssociationTransportError(t *testing.T) {
	srv, addr := pcfTLSServer(t, func(http.ResponseWriter, *http.Request) {})
	client := srv.Client()
	srv.Close()
	if err := (&HTTPAMPolicyClient{address: addr, client: client}).DeleteAMPolicyAssociation(context.Background(), "p1"); err == nil {
		t.Error("AM: transport error must not be swallowed")
	}
	if err := (&HTTPPCFClient{address: addr, client: client}).DeleteUEPolicyAssociation(context.Background(), "p1"); err == nil {
		t.Error("UE: transport error must not be swallowed")
	}
}
