package sbi

import (
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/francurieses/claudia-5gc/shared/observability/metrics"
	dto "github.com/prometheus/client_model/go"
)

func procCount(t *testing.T, nf, result string) float64 {
	t.Helper()
	var m dto.Metric
	if err := metrics.ProcedureTotal.WithLabelValues(nf, "HttpRedirection", result).Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

// TestRedirectCountsProcedureTotal checks that every redirect record
// increments fivegc_procedure_total{procedure="HttpRedirection"} with the
// result of the record (OK followed, FAILURE refused).
func TestRedirectCountsProcedureTotal(t *testing.T) {
	const nf = "TESTNF"
	b := newPeer(t, created)
	a := newPeer(t, func(p *peer, w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("bad") != "" {
			w.Header().Set("Location", b.url()+r.URL.Path)
			w.WriteHeader(http.StatusFound) // 302: not followed
			return
		}
		w.Header().Set("Location", b.url()+r.URL.Path)
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	c := a.srv.Client()
	ApplyRedirectPolicy(c, slog.New(slog.NewJSONHandler(io.Discard, nil)), WithNF(nf))

	okBefore, failBefore := procCount(t, nf, "OK"), procCount(t, nf, "FAILURE")

	resp, err := post(t, c, a.url()+"/nsmf-pdusession/v1/sm-contexts", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if d := procCount(t, nf, "OK") - okBefore; d != 1 {
		t.Errorf("OK delta = %v, want 1", d)
	}

	resp, err = post(t, c, a.url()+"/nsmf-pdusession/v1/sm-contexts?bad=1", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if d := procCount(t, nf, "FAILURE") - failBefore; d != 1 {
		t.Errorf("FAILURE delta = %v, want 1", d)
	}
}
