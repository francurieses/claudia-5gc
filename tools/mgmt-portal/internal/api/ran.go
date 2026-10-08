package api

// ran.go — gNBs (RAN) page backend.
//
// GET /api/v1/ran/gnbs aggregates the AMF gNB registries
// (GET /amf/v1/ran/gnbs on each AMF management endpoint). The data comes from
// the AMF's NG Setup / SCTP state, never from Docker, so it is valid in every
// deployment mode.
//
// Ref: TS 38.413 §8.7.1 (NG Setup), TS 38.412 §7 (SCTP).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// ranSourceTimeout bounds each AMF query. Lab UX value, not a 3GPP timer.
const ranSourceTimeout = 3 * time.Second

// ranSource is the outcome of querying one AMF.
type ranSource struct {
	AMFURL  string `json:"amf_url"`
	AMFName string `json:"amf_name,omitempty"`
	N2Addr  string `json:"n2_addr,omitempty"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

// RANGnbsResponse is returned by GET /api/v1/ran/gnbs.
type RANGnbsResponse struct {
	GNBs        []map[string]any `json:"gnbs"`
	Sources     []ranSource      `json:"sources"`
	GeneratedAt time.Time        `json:"generated_at"`
}

type amfGNBEnvelope struct {
	AMF  map[string]any   `json:"amf"`
	GNBs []map[string]any `json:"gnbs"`
}

// amfMgmtURLs returns the AMF management endpoints to query.
func (d Deps) amfMgmtURLs() []string {
	if len(d.AMFMgmtURLs) > 0 {
		return d.AMFMgmtURLs
	}
	if d.AMFBaseURL != "" {
		return []string{d.AMFBaseURL}
	}
	return nil
}

func queryAMFGNBs(ctx context.Context, base string) (amfGNBEnvelope, error) {
	var env amfGNBEnvelope
	ctx, cancel := context.WithTimeout(ctx, ranSourceTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/amf/v1/ran/gnbs", nil)
	if err != nil {
		return env, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return env, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return env, fmt.Errorf("AMF returned HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return env, fmt.Errorf("decode AMF response: %w", err)
	}
	return env, nil
}

func ranStateRank(g map[string]any) int {
	switch g["state"] {
	case "NG_READY":
		return 0
	case "SCTP_UP":
		return 1
	}
	return 2
}

// handleRANGnbs serves GET /api/v1/ran/gnbs. It answers 200 even when every AMF
// is unreachable: the per-source status tells the page what to show.
func (d Deps) handleRANGnbs(w http.ResponseWriter, r *http.Request) {
	urls := d.amfMgmtURLs()
	sources := make([]ranSource, len(urls))
	results := make([]amfGNBEnvelope, len(urls))

	var wg sync.WaitGroup
	for i, u := range urls {
		wg.Add(1)
		go func(i int, u string) {
			defer wg.Done()
			env, err := queryAMFGNBs(r.Context(), u)
			sources[i] = ranSource{AMFURL: u, OK: err == nil}
			if err != nil {
				sources[i].Error = err.Error()
				return
			}
			results[i] = env
			if n, ok := env.AMF["name"].(string); ok {
				sources[i].AMFName = n
			}
			if a, ok := env.AMF["n2_addr"].(string); ok {
				sources[i].N2Addr = a
			}
		}(i, u)
	}
	wg.Wait()

	gnbs := []map[string]any{}
	for i, env := range results {
		for _, g := range env.GNBs {
			g["amf"] = map[string]any{"url": urls[i], "name": sources[i].AMFName}
			gnbs = append(gnbs, g)
		}
	}
	sort.SliceStable(gnbs, func(i, j int) bool {
		if ri, rj := ranStateRank(gnbs[i]), ranStateRank(gnbs[j]); ri != rj {
			return ri < rj
		}
		ni, _ := gnbs[i]["ran_node_name"].(string)
		nj, _ := gnbs[j]["ran_node_name"].(string)
		return ni < nj
	})

	writeJSON(w, http.StatusOK, RANGnbsResponse{GNBs: gnbs, Sources: sources, GeneratedAt: time.Now().UTC()})
}
