package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Obs wraps the Jaeger and Prometheus query APIs for the Group D tools.
type Obs struct {
	jaegerURL     string
	prometheusURL string
	http          *http.Client
}

// NewObs builds an observability client.
func NewObs(jaegerURL, prometheusURL string, httpClient *http.Client) *Obs {
	return &Obs{
		jaegerURL:     strings.TrimRight(jaegerURL, "/"),
		prometheusURL: strings.TrimRight(prometheusURL, "/"),
		http:          httpClient,
	}
}

// JaegerTraces queries the Jaeger HTTP API for traces of a service, optionally
// filtered by tags (e.g. {"correlation_id": "..."}). limit bounds the result.
func (c *Obs) JaegerTraces(ctx context.Context, service string, tags map[string]string, limit int) (json.RawMessage, error) {
	q := url.Values{}
	q.Set("service", service)
	if limit > 0 {
		q.Set("limit", fmt.Sprintf("%d", limit))
	}
	if len(tags) > 0 {
		tagJSON, _ := json.Marshal(tags)
		q.Set("tags", string(tagJSON))
	}
	return c.getJSON(ctx, c.jaegerURL+"/api/traces?"+q.Encode())
}

// JaegerTrace fetches a single trace by id.
func (c *Obs) JaegerTrace(ctx context.Context, traceID string) (json.RawMessage, error) {
	return c.getJSON(ctx, c.jaegerURL+"/api/traces/"+url.PathEscape(traceID))
}

// PromQuery runs an instant PromQL query against the Prometheus HTTP API.
func (c *Obs) PromQuery(ctx context.Context, query string) (json.RawMessage, error) {
	q := url.Values{}
	q.Set("query", query)
	return c.getJSON(ctx, c.prometheusURL+"/api/v1/query?"+q.Encode())
}

func (c *Obs) getJSON(ctx context.Context, u string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("obs: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("obs: request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("obs: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("obs: GET %s: status %d", u, resp.StatusCode)
	}
	return body, nil
}
