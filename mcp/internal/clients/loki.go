package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Loki wraps the Loki query API (plain HTTP on obs-net, default loki:3100). It
// returns the log lines the NFs ship through Promtail, which are JSON records
// with nf, procedure, correlation_id and result fields.
type Loki struct {
	baseURL string
	http    *http.Client
}

// NewLoki builds a Loki client.
func NewLoki(baseURL string, httpClient *http.Client) *Loki {
	return &Loki{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
}

// LokiLine is one log line with its stream labels and timestamp.
type LokiLine struct {
	Time   time.Time         `json:"time"`
	Labels map[string]string `json:"labels"`
	Line   string            `json:"line"`
}

// QueryRange runs a LogQL range query, newest-first capped at limit, and returns
// the lines sorted by time ascending.
func (l *Loki) QueryRange(ctx context.Context, logql string, start, end time.Time, limit int) ([]LokiLine, error) {
	q := url.Values{}
	q.Set("query", logql)
	q.Set("start", strconv.FormatInt(start.UnixNano(), 10))
	q.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	q.Set("limit", strconv.Itoa(limit))
	q.Set("direction", "backward")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.baseURL+"/loki/api/v1/query_range?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("loki: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := l.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("loki: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("loki: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("loki: status %d: %s", resp.StatusCode, truncate(body))
	}
	var res struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Stream map[string]string `json:"stream"`
				Values [][2]string       `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("loki: decode response: %w", err)
	}
	if res.Status != "success" {
		return nil, fmt.Errorf("loki: non-success status %q", res.Status)
	}
	var out []LokiLine
	for _, s := range res.Data.Result {
		for _, v := range s.Values {
			ns, err := strconv.ParseInt(v[0], 10, 64)
			if err != nil {
				continue
			}
			out = append(out, LokiLine{Time: time.Unix(0, ns).UTC(), Labels: s.Stream, Line: v[1]})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out, nil
}

// LokiSample is one series of an instant metric query: the grouping labels and the value.
type LokiSample struct {
	Labels map[string]string
	Value  float64
}

// QueryMetric runs a LogQL instant metric query (GET /loki/api/v1/query) at the
// given time (zero means now) and returns the vector. Any other result type is an
// error: the caller asked for a metric expression, not a log selector.
func (l *Loki) QueryMetric(ctx context.Context, logql string, at time.Time) ([]LokiSample, error) {
	q := url.Values{}
	q.Set("query", logql)
	if !at.IsZero() {
		q.Set("time", strconv.FormatInt(at.UnixNano(), 10))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.baseURL+"/loki/api/v1/query?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("loki: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := l.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("loki: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("loki: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("loki: status %d: %s", resp.StatusCode, truncate(body))
	}
	var res struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Metric map[string]string  `json:"metric"`
				Value  [2]json.RawMessage `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("loki: decode response: %w", err)
	}
	if res.Status != "success" {
		return nil, fmt.Errorf("loki: non-success status %q", res.Status)
	}
	if res.Data.ResultType != "vector" {
		return nil, fmt.Errorf("loki: metric query returned resultType %q, want vector", res.Data.ResultType)
	}
	out := make([]LokiSample, 0, len(res.Data.Result))
	for _, r := range res.Data.Result {
		var s string
		if err := json.Unmarshal(r.Value[1], &s); err != nil {
			continue
		}
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			continue
		}
		out = append(out, LokiSample{Labels: r.Metric, Value: v})
	}
	return out, nil
}
