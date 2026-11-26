package procedures

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
	"github.com/francurieses/claudia-5gc/nf/amf/internal/roaming"
	"github.com/francurieses/claudia-5gc/shared/nas"
)

func TestRejectCauseForRoamingAUSFError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want nas.Cause5GMM
	}{
		{"403 SNNA", &AUSFError{Op: "initiate auth", Status: http.StatusForbidden, Cause: AUSFCauseServingNetworkNotAuthorized}, nas.CauseServingNetworkNotAuthorized},
		{"403 SNNA wrapped", fmt.Errorf("ausf: x: %w", &AUSFError{Status: 403, Cause: AUSFCauseServingNetworkNotAuthorized}), nas.CauseServingNetworkNotAuthorized},
		{"403 other cause", &AUSFError{Status: 403, Cause: "OTHER"}, NFUnavailableRejectCause},
		{"SEPP 504", &AUSFError{Status: 504, Cause: "TARGET_NF_NOT_REACHABLE"}, NFUnavailableRejectCause},
		{"transport", errors.New("dial tcp: refused"), NFUnavailableRejectCause},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, ref := RejectCauseForRoamingAUSFError(tc.err); got != tc.want || ref == "" {
				t.Fatalf("cause = %d (%q), want %d", got, ref, tc.want)
			}
		})
	}
}

// The typed error renders exactly like the pre-ROAM-001 untyped error.
func TestAUSFErrorLegacyText(t *testing.T) {
	if got, want := (&AUSFError{Op: "initiate auth", Status: 403, Cause: "X"}).Error(), "ausf: initiate auth: status 403 cause=X"; got != want {
		t.Fatalf("%q != %q", got, want)
	}
	if got, want := (&AUSFError{Op: "confirm auth", Status: 500}).Error(), "ausf: confirm auth: status 500 cause=<nil>"; got != want {
		t.Fatalf("%q != %q", got, want)
	}
}

func roamingTestHandler(t *testing.T, enabled bool) *RegistrationHandler {
	t.Helper()
	h := NewRegistrationHandler(nil, nil, nil, nil, "nf", "001", "01", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if enabled {
		r, err := roaming.New(roaming.Config{Enabled: true, SEPPAddress: "sepp:8014", HomePLMNs: []roaming.HomePLMN{{
			PLMN:        roaming.PLMN{MCC: "001", MNC: "02"},
			AUSFAPIRoot: "https://ausf.5gc.mnc002.mcc001.3gppnetwork.org:8002",
			UDMAPIRoot:  "https://udm.5gc.mnc002.mcc001.3gppnetwork.org:8003",
		}}}, "001", "01")
		if err != nil {
			t.Fatal(err)
		}
		h.WithRoaming(r)
	}
	return h
}

func TestSelectHomeRoute(t *testing.T) {
	tests := []struct {
		name      string
		enabled   bool
		identity  string
		wantRoute bool
		wantCause nas.Cause5GMM // 0 = no reject
	}{
		{"roaming UE", true, "suci-0-001-02-0-0-0-0000000001", true, 0},
		{"local UE", true, "suci-0-001-01-0-0-0-0000000001", false, 0},
		{"unconfigured home PLMN -> #11", true, "suci-0-001-03-0-0-0-0000000001", false, nas.CausePLMNNotAllowed},
		{"roaming disabled: 001/02 SUCI stays local", false, "suci-0-001-02-0-0-0-0000000001", false, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := roamingTestHandler(t, tc.enabled)
			ue := &amfctx.UEContext{}
			ctx, err := h.selectHomeRoute(t.Context(), ue, tc.identity, h.logger)
			if tc.wantCause != 0 {
				var rc *ErrRejectCause
				if !errors.As(err, &rc) || rc.Cause != tc.wantCause {
					t.Fatalf("err = %v, want reject #%d", err, tc.wantCause)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := ue.HomeRoute() != nil; got != tc.wantRoute {
				t.Fatalf("ue route set = %v, want %v", got, tc.wantRoute)
			}
			if got := roaming.RouteFrom(ctx) != nil; got != tc.wantRoute {
				t.Fatalf("ctx route set = %v, want %v", got, tc.wantRoute)
			}
		})
	}
}

func TestAUSFFailureCauses(t *testing.T) {
	h := roamingTestHandler(t, true)
	snna := &AUSFError{Op: "initiate auth", Status: 403, Cause: AUSFCauseServingNetworkNotAuthorized}

	local := &amfctx.UEContext{}
	var rc *ErrRejectCause
	if err := h.ausfFailure(local, h.logger, "initiate auth", snna); !errors.As(err, &rc) || rc.Cause != NFUnavailableRejectCause {
		t.Fatalf("local path must stay #22, got %v", err)
	}

	roam := &amfctx.UEContext{}
	_, _ = h.selectHomeRoute(t.Context(), roam, "suci-0-001-02-0-0-0-1", h.logger)
	if err := h.ausfFailure(roam, h.logger, "initiate auth", snna); !errors.As(err, &rc) || rc.Cause != nas.CauseServingNetworkNotAuthorized {
		t.Fatalf("roaming SNNA must be #73, got %v", err)
	}
	sepp504 := &AUSFError{Op: "initiate auth", Status: 504, Cause: "TARGET_NF_NOT_REACHABLE"}
	if err := h.ausfFailure(roam, h.logger, "initiate auth", sepp504); !errors.As(err, &rc) || rc.Cause != NFUnavailableRejectCause {
		t.Fatalf("roaming 504 must be #22, got %v", err)
	}
}

// A 5G-GUTI (or any identity without a home network) never overwrites the
// route of the UE context; an unparsable SUCI is logged and clears it.
func TestSelectHomeRouteKeepsRouteWithoutClassification(t *testing.T) {
	var buf bytes.Buffer
	h := roamingTestHandler(t, true)
	log := slog.New(slog.NewTextHandler(&buf, nil))
	ue := &amfctx.UEContext{}
	if _, err := h.selectHomeRoute(t.Context(), ue, "suci-0-001-02-0-0-0-0000000001", log); err != nil || ue.HomeRoute() == nil {
		t.Fatalf("setup: route %v err %v", ue.HomeRoute(), err)
	}
	want := ue.HomeRoute()
	buf.Reset()

	ctx, err := h.selectHomeRoute(t.Context(), ue, "5g-guti-00101ca010000abcd", log)
	if err != nil || ue.HomeRoute() != want || roaming.RouteFrom(ctx) != want {
		t.Fatalf("GUTI must keep the route: ue %v ctx %v err %v", ue.HomeRoute(), roaming.RouteFrom(ctx), err)
	}
	if buf.Len() != 0 {
		t.Fatalf("GUTI must not log a warning: %s", buf.String())
	}

	if _, err := h.selectHomeRoute(t.Context(), ue, "suci-bogus", log); err != nil || ue.HomeRoute() != nil {
		t.Fatalf("unparsable SUCI: route %v err %v", ue.HomeRoute(), err)
	}
	if !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), "not parsable") {
		t.Fatalf("unparsable SUCI must log WARN: %s", buf.String())
	}

	// Roaming off: nothing is logged, today's behaviour.
	buf.Reset()
	off := roamingTestHandler(t, false)
	if _, err := off.selectHomeRoute(t.Context(), &amfctx.UEContext{}, "suci-bogus", log); err != nil || buf.Len() != 0 {
		t.Fatalf("roaming off: err %v log %s", err, buf.String())
	}
}

// ueRouteCtx marks a roaming UE so a client without a route fails.
func TestUERouteCtx(t *testing.T) {
	h := roamingTestHandler(t, true)
	ue := &amfctx.UEContext{}
	if c := ueRouteCtx(t.Context(), ue); roaming.RoamingRequired(c) || roaming.RouteFrom(c) != nil {
		t.Fatal("non-roaming UE ctx must be untouched")
	}
	_, _ = h.selectHomeRoute(t.Context(), ue, "suci-0-001-02-0-0-0-1", h.logger)
	if c := ueRouteCtx(t.Context(), ue); !roaming.RoamingRequired(c) || roaming.RouteFrom(c) == nil {
		t.Fatal("roaming UE ctx must carry route and mark")
	}
}
