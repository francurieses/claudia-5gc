package api

// release.go — GET /api/v1/release reports the 3GPP release profile the running
// core was started with (shared/capability, NF_RELEASE_PROFILE). It is derived
// from each NF's startup log line, read through the Docker SDK:
//
//	AMF/AUSF/UDM/...  {"msg":"release profile loaded","release_profile":"rel19"}
//	SMF               {"msg":"SMF release profile","release_profile":"rel19"}
//
// The last such line wins (the container may have restarted). Results are
// cached briefly so the sidebar poll never hammers the Docker socket.

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	releaseCacheTTL   = 30 * time.Second
	releaseReadBudget = 4 * time.Second

	// Profile values of the aggregate answer.
	profileMixed   = "mixed"
	profileUnknown = "unknown"
)

// releaseNFs are the core NF containers inspected, in display order.
var releaseNFs = []string{"amf", "smf", "pcf", "nrf", "ausf", "udm", "udr", "nssf", "smsf", "bsf", "nef", "lmf"}

// ReleaseInfo is the GET /api/v1/release response.
type ReleaseInfo struct {
	Profile string            `json:"profile"` // rel19 | rel17 | mixed | unknown
	NFs     map[string]string `json:"nfs"`
}

// StartupLogReader returns the startup log of a container ("" when it is
// missing or stopped).
type StartupLogReader interface {
	StartupLogs(ctx context.Context, name string) (string, error)
}

// ReleaseResolver resolves and caches the core's release profile.
type ReleaseResolver struct {
	src StartupLogReader
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	cached  ReleaseInfo
	expires time.Time
}

// NewReleaseResolver returns a resolver reading NF startup logs from src.
func NewReleaseResolver(src StartupLogReader) *ReleaseResolver {
	return &ReleaseResolver{src: src, ttl: releaseCacheTTL, now: time.Now}
}

// Get returns the (cached) release info.
func (r *ReleaseResolver) Get(ctx context.Context) ReleaseInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.now().Before(r.expires) {
		return r.cached
	}
	ctx, cancel := context.WithTimeout(ctx, releaseReadBudget)
	defer cancel()

	type res struct{ nf, profile string }
	ch := make(chan res, len(releaseNFs))
	for _, nf := range releaseNFs {
		go func(nf string) {
			logs, err := r.src.StartupLogs(ctx, nf)
			if err != nil {
				ch <- res{nf, ""}
				return
			}
			ch <- res{nf, parseReleaseProfile(logs)}
		}(nf)
	}
	nfs := map[string]string{}
	for range releaseNFs {
		if x := <-ch; x.profile != "" {
			nfs[x.nf] = x.profile
		}
	}
	r.cached = ReleaseInfo{Profile: aggregateProfile(nfs), NFs: nfs}
	r.expires = r.now().Add(r.ttl)
	return r.cached
}

// parseReleaseProfile returns release_profile from the LAST startup profile
// line in logs, or "".
func parseReleaseProfile(logs string) string {
	profile := ""
	sc := bufio.NewScanner(strings.NewReader(logs))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, "release profile") {
			continue
		}
		i := strings.IndexByte(line, '{')
		if i < 0 {
			continue
		}
		var m struct {
			Msg     string `json:"msg"`
			Profile string `json:"release_profile"`
		}
		if json.Unmarshal([]byte(line[i:]), &m) != nil || m.Profile == "" {
			continue
		}
		if m.Msg == "release profile loaded" || m.Msg == "SMF release profile" {
			profile = m.Profile
		}
	}
	return profile
}

func aggregateProfile(nfs map[string]string) string {
	common := ""
	for _, p := range nfs {
		switch {
		case common == "":
			common = p
		case common != p:
			return profileMixed
		}
	}
	if common == "" {
		return profileUnknown
	}
	return common
}

// handleRelease serves GET /api/v1/release.
func (d Deps) handleRelease(w http.ResponseWriter, r *http.Request) {
	if d.Release == nil {
		writeJSON(w, http.StatusOK, ReleaseInfo{Profile: profileUnknown, NFs: map[string]string{}})
		return
	}
	writeJSON(w, http.StatusOK, d.Release.Get(r.Context()))
}
