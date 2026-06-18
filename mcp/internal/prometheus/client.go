// Package prometheus provides a thin HTTP client for the Prometheus query API.
// It wraps /api/v1/query (instant query) and /api/v1/alerts without pulling in
// the full Prometheus client library.
package prometheus

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client queries the Prometheus HTTP API.
type Client struct {
	base    string
	http    *http.Client
	timeout time.Duration
}

// New returns a Client for the given Prometheus base URL.
// If httpClient is nil, http.DefaultClient is used.
func New(baseURL string, httpClient *http.Client, queryTimeout time.Duration) *Client {
	if queryTimeout <= 0 {
		queryTimeout = 5 * time.Second
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{
		base:    strings.TrimRight(baseURL, "/"),
		http:    httpClient,
		timeout: queryTimeout,
	}
}

// QueryResult is the structured response from /api/v1/query.
type QueryResult struct {
	Status string     `json:"status"`
	Data   QueryData  `json:"data"`
}

// QueryData holds the result type and result set.
type QueryData struct {
	ResultType string        `json:"resultType"`
	Result     []VectorSample `json:"result"`
}

// VectorSample is one instant-query result row.
type VectorSample struct {
	Metric map[string]string `json:"metric"`
	Value  [2]json.RawMessage `json:"value"` // [timestamp, "value_string"]
}

// Float64 parses the string value of a VectorSample. Returns NaN on error.
func (v VectorSample) Float64() float64 {
	var s string
	if err := json.Unmarshal(v.Value[1], &s); err != nil {
		return 0
	}
	var f float64
	fmt.Sscanf(s, "%f", &f)
	return f
}

// AlertsResult is the structured response from /api/v1/alerts.
type AlertsResult struct {
	Status string     `json:"status"`
	Data   AlertsData `json:"data"`
}

// AlertsData holds the alert slice.
type AlertsData struct {
	Alerts []Alert `json:"alerts"`
}

// Alert represents one Prometheus alert.
type Alert struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	State       string            `json:"state"`
	ActiveAt    string            `json:"activeAt"`
	Value       string            `json:"value"`
}

// Query executes an instant PromQL query. If ts is zero, uses now.
func (c *Client) Query(ctx context.Context, promql string, ts time.Time) (*QueryResult, error) {
	tCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	q := url.Values{}
	q.Set("query", promql)
	if !ts.IsZero() {
		q.Set("time", ts.UTC().Format(time.RFC3339))
	}
	req, err := http.NewRequestWithContext(tCtx, http.MethodGet, c.base+"/api/v1/query?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("prometheus query: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prometheus query: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("prometheus query: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prometheus query: status %d: %s", resp.StatusCode, body)
	}

	var res QueryResult
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("prometheus query: decode response: %w", err)
	}
	if res.Status != "success" {
		return nil, fmt.Errorf("prometheus query: non-success status: %s", res.Status)
	}
	return &res, nil
}

// QueryScalar runs a scalar PromQL expression (e.g. a rate/ratio) and returns
// the first result value, or 0.0 if there are no results.
func (c *Client) QueryScalar(ctx context.Context, promql string) (float64, error) {
	res, err := c.Query(ctx, promql, time.Time{})
	if err != nil {
		return 0, err
	}
	if len(res.Data.Result) == 0 {
		return 0, nil
	}
	return res.Data.Result[0].Float64(), nil
}

// Alerts fetches all alerts from /api/v1/alerts. Returns an empty list if
// Prometheus has no alerts configured.
func (c *Client) Alerts(ctx context.Context) ([]Alert, error) {
	tCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(tCtx, http.MethodGet, c.base+"/api/v1/alerts", nil)
	if err != nil {
		return nil, fmt.Errorf("prometheus alerts: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prometheus alerts: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("prometheus alerts: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prometheus alerts: status %d", resp.StatusCode)
	}

	var res AlertsResult
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("prometheus alerts: decode response: %w", err)
	}
	if res.Data.Alerts == nil {
		return []Alert{}, nil
	}
	return res.Data.Alerts, nil
}
