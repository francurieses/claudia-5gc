package main

// roaming_route.go - per-call roaming route for the Nausf/Nudm consumers
// (ROAM-001). A route found on the request context (or, for SUPI-only calls,
// remembered for the SUPI) sends the request to the SEPP with the home NF
// apiRoot in 3gpp-Sbi-Target-apiRoot; without a route nothing changes, so a
// non-roaming request is byte-identical with roaming enabled or disabled.
//
// Ref: TS 29.500 §6.1.4.3; TS 23.502 §4.2.2.2.2; TS 33.501 §6.1.3.2

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/francurieses/claudia-5gc/nf/amf/internal/roaming"
	"github.com/francurieses/claudia-5gc/shared/logging"
)

// routedTarget returns the URL for path and, when rt is non-nil, the roaming
// hop (URL on the SEPP). local is the locally configured peer address.
func routedTarget(rt *roaming.Route, nf roaming.NF, local, path string) (string, *roaming.Hop) {
	if rt == nil {
		return "https://" + local + path, nil
	}
	hop := rt.Hop(nf)
	return hop.URL(path), &hop
}

// applyHop sets the target-apiRoot header and the originating PLMN on a request
// routed through the SEPP. The 3gpp-Sbi-Originating-Network-Id value is the
// serving PLMN as "mcc-mnc" (ABNF 3DIGIT "-" 2*3DIGIT, TS 29.500 §5.2.3.2.15).
// Ref: TS 29.500 §5.2.3.2.15, §6.1.4.3; TS 33.501 §5.9.3.5
func applyHop(req *http.Request, hop *roaming.Hop) {
	if hop == nil {
		return
	}
	req.Header.Set(roaming.TargetAPIRootHeader, hop.APIRoot)
	if id := hop.OriginatingNetworkID(); id != "" {
		req.Header.Set(roaming.OriginatingNetworkIDHeader, id)
	}
}

// requireRoute fails a request of a UE known to be roaming (ctx marked by
// roaming.WithRoamingRequired) that has no usable route, instead of letting it
// go to the local AUSF/UDM.
func requireRoute(ctx context.Context, rt *roaming.Route) error {
	if rt == nil && roaming.RoamingRequired(ctx) || rt != nil && rt.ViaSEPP == "" {
		return roaming.ErrNoRoute
	}
	return nil
}

// logRoamingHop writes the canonical record of a request routed via the SEPP.
func logRoamingHop(ctx context.Context, base *slog.Logger, iface, procedure, specRef string,
	rt *roaming.Route, hop *roaming.Hop, extra ...any) {
	if hop == nil {
		return
	}
	if base == nil {
		base = slog.Default()
	}
	args := append([]any{
		"interface", iface, "direction", "OUT", "roaming", true,
		"home_plmn", rt.HomePLMN.String(), "via_sepp", hop.ViaSEPP,
		"target_api_root", hop.APIRoot, "spec_ref", specRef,
	}, extra...)
	logging.NewProcedureLogger(ctx, base, procedure).Info("request routed via SEPP to home PLMN", args...)
}
