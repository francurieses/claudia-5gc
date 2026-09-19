// Package prometheus provides a thin client for the Prometheus HTTP API.
package prometheus

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Client queries the Prometheus HTTP API.
type Client struct {
	baseURL string
	http    *http.Client
}

// New returns a Client for the given Prometheus base URL.
func New(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		http:    &http.Client{Timeout: 5 * time.Second},
	}
}

// Sample is a Prometheus instant vector sample.
type Sample struct {
	Metric map[string]string `json:"metric"`
	Value  [2]interface{}    `json:"value"` // [timestamp, "value"]
}

// QueryResult holds the result of an instant query.
type QueryResult struct {
	Data struct {
		Result []Sample `json:"result"`
	} `json:"data"`
}

// Query executes an instant PromQL query and returns samples.
func (c *Client) Query(ctx context.Context, expr string) ([]Sample, error) {
	u := c.baseURL + "/api/v1/query?query=" + url.QueryEscape(expr)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prometheus: query %q: %w", expr, err)
	}
	defer resp.Body.Close()

	var result QueryResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("prometheus: decode: %w", err)
	}
	return result.Data.Result, nil
}

// MatrixSeries is one time series returned by a range query. Each value is
// [unix_seconds, "value"] exactly as the Prometheus HTTP API encodes it (the
// value is a string so NaN/Inf survive the wire).
type MatrixSeries struct {
	Metric map[string]string `json:"metric"`
	Values [][2]interface{}  `json:"values"`
}

// RangeResult holds the result payload of a range query (resultType "matrix").
type RangeResult struct {
	Data struct {
		Result []MatrixSeries `json:"result"`
	} `json:"data"`
}

// QueryRange executes a Prometheus range query (query_range) and returns the
// matrix series. start/end are sent as Unix seconds and step as a "<n>s"
// duration, matching the Prometheus HTTP API.
func (c *Client) QueryRange(ctx context.Context, expr string, start, end time.Time, stepSeconds int) ([]MatrixSeries, error) {
	q := url.Values{}
	q.Set("query", expr)
	q.Set("start", strconv.FormatInt(start.Unix(), 10))
	q.Set("end", strconv.FormatInt(end.Unix(), 10))
	q.Set("step", strconv.Itoa(stepSeconds)+"s")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/query_range?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prometheus: query_range %q: %w", expr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prometheus: query_range %q: unexpected status %d", expr, resp.StatusCode)
	}

	var result RangeResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("prometheus: decode: %w", err)
	}
	return result.Data.Result, nil
}

// MetricsSummary holds the key metrics shown in the dashboard.
//
// RegistrationSuccessPct and PDUSessionEstablishmentSuccessPct are nullable
// instant KPIs over a fixed [summaryWindow]: nil (JSON null) means the window
// had no data (or the ratio was NaN), which the UI renders as "—" — never a
// fabricated 0% or 100% (PORTAL-UI-21).
type MetricsSummary struct {
	UERegistered               int                `json:"ue_registered"`
	PDUSessions                int                `json:"pdu_sessions"`
	RegistrationSuccessPct     *float64           `json:"registration_success_pct"`
	PDUSessionEstablishmentPct *float64           `json:"pdu_session_establishment_success_pct"`
	ProcedureRates             map[string]float64 `json:"procedure_rates"`
	NFUp                       map[string]bool    `json:"nf_up"`
}

// summaryWindow is the look-back window for the instant success-rate KPIs on
// the dashboard summary. Five minutes ≈ 30 scrapes at the 10 s scrape
// interval: responsive enough for a status view, stable enough not to flicker.
// Ref: TS 28.554 §5.1 (registration success rate), §5.2 (PDU session
// establishment success rate).
const summaryWindow = "5m"

// Summary fetches and assembles the dashboard metrics summary.
func (c *Client) Summary(ctx context.Context) MetricsSummary {
	summary := MetricsSummary{
		ProcedureRates: map[string]float64{},
		NFUp:           map[string]bool{},
	}

	nfPorts := map[string]string{
		"nrf":  "9100",
		"amf":  "9101",
		"ausf": "9102",
		"udm":  "9103",
		"udr":  "9104",
		"smf":  "9105",
		"pcf":  "9106",
		"upf":  "9107",
		"nssf": "9109",
		"smsf": "9110",
		"bsf":  "9111",
		"nef":  "9112",
	}

	for nf, port := range nfPorts {
		samples, err := c.Query(ctx, fmt.Sprintf(`up{instance="%s:%s"}`, nf, port))
		if err == nil && len(samples) > 0 {
			if v, ok := samples[0].Value[1].(string); ok {
				summary.NFUp[nf] = v == "1"
			}
		}
	}

	if samples, err := c.Query(ctx, `sum(fivegc_ue_registered)`); err == nil && len(samples) > 0 {
		if v, ok := samples[0].Value[1].(string); ok {
			fmt.Sscanf(v, "%d", &summary.UERegistered)
		}
	}

	// Stale-metric fix: the old fallback queried count(smf_sessions_total), a
	// series that no longer exists (SMF exposes the gauge
	// fivegc_pdu_sessions_active), so it always returned 0. Sum the gauge
	// instead; `or vector(0)` keeps the zero fallback when nothing is up.
	// Ref: shared/observability/metrics/metrics.go.
	if samples, err := c.Query(ctx, `sum(fivegc_pdu_sessions_active) or vector(0)`); err == nil && len(samples) > 0 {
		if v, ok := samples[0].Value[1].(string); ok {
			fmt.Sscanf(v, "%d", &summary.PDUSessions)
		}
	}

	// Instant 5-minute success-rate KPIs (PORTAL-UI-21). Both are ratios over a
	// fixed window; a window with no attempts yields 0/0 = NaN, which
	// instantRatio maps to nil so the card shows "—".
	summary.RegistrationSuccessPct = c.instantRatio(ctx, fmt.Sprintf(
		`100 * sum(rate(fivegc_procedure_total{nf="AMF",procedure="InitialRegistration",result="OK"}[%s])) / sum(rate(fivegc_procedure_total{nf="AMF",procedure="InitialRegistration"}[%s]))`,
		summaryWindow, summaryWindow))
	summary.PDUSessionEstablishmentPct = c.instantRatio(ctx, fmt.Sprintf(
		`100 * sum(rate(fivegc_pdu_session_total{result="OK"}[%s])) / sum(rate(fivegc_pdu_session_total[%s]))`,
		summaryWindow, summaryWindow))

	return summary
}

// instantRatio evaluates an instant PromQL expression expected to yield a
// single scalar and returns it as a *float64, or nil when the query fails,
// returns no sample, or the sample is non-finite (NaN/±Inf). nil is the honest
// "no data in the window" signal — the UI must not turn it into 0% or 100%
// (TS 28.554 §5.1/§5.2).
func (c *Client) instantRatio(ctx context.Context, expr string) *float64 {
	samples, err := c.Query(ctx, expr)
	if err != nil || len(samples) == 0 {
		return nil
	}
	raw, ok := samples[0].Value[1].(string)
	if !ok {
		return nil
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return nil
	}
	return &v
}
