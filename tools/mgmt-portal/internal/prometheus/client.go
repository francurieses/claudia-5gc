// Package prometheus provides a thin client for the Prometheus HTTP API.
package prometheus

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

// MetricsSummary holds the key metrics shown in the dashboard.
type MetricsSummary struct {
	UERegistered   int                    `json:"ue_registered"`
	PDUSessions    int                    `json:"pdu_sessions"`
	ProcedureRates map[string]float64     `json:"procedure_rates"`
	NFUp           map[string]bool        `json:"nf_up"`
}

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

	if samples, err := c.Query(ctx, `count(smf_sessions_total) or vector(0)`); err == nil && len(samples) > 0 {
		if v, ok := samples[0].Value[1].(string); ok {
			fmt.Sscanf(v, "%d", &summary.PDUSessions)
		}
	}

	return summary
}
