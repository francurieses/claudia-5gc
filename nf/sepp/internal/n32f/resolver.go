package n32f

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/francurieses/claudia-5gc/shared/nrf"
)

const (
	// requesterNFType is the requester-nf-type sent in NFDiscover. Ref: TS 29.510 §6.2.3.2.3.1.
	requesterNFType = "SEPP"
	// resolveTTL caches a discovery answer (implementation choice; the NRF
	// validityPeriod is not used so a stale entry is bounded and short).
	resolveTTL = 30 * time.Second
	// maxResolveCache bounds the resolver cache.
	maxResolveCache = 1024
)

// ErrTargetNotFound means the NRF knows no NF with the requested FQDN.
var ErrTargetNotFound = errors.New("n32f: resolve: target NF not found in NRF")

// Resolver finds the local NF that serves an inbound request: it returns the
// scheme://host[:port] to forward to. Peers are never taken from configuration
// (CLAUDE.md: discover via NRF).
type Resolver interface {
	Resolve(ctx context.Context, targetHost, path string) (*url.URL, error)
}

// Discoverer is the NRF client subset the resolver needs (*nrf.Client).
type Discoverer interface {
	Discover(ctx context.Context, q nrf.DiscoveryQuery) (*nrf.SearchResult, error)
}

// serviceNFType maps the API name prefix of the request path to the producer
// NF type. Ref: TS 29.510 Table 6.1.6.3.11-1 (service names).
var serviceNFType = map[string]string{
	"namf": "AMF", "nsmf": "SMF", "nnrf": "NRF", "nudm": "UDM", "nudr": "UDR",
	"nausf": "AUSF", "npcf": "PCF", "nnssf": "NSSF", "nchf": "CHF", "nnef": "NEF",
	"nbsf": "BSF", "nlmf": "LMF", "ngmlc": "GMLC", "nsepp": "SEPP",
}

// NRFResolver implements Resolver with Nnrf_NFDiscovery (TS 29.510 §5.3.2.2).
type NRFResolver struct {
	nrf Discoverer
	now func() time.Time

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	u   url.URL
	exp time.Time
}

// NewNRFResolver returns a resolver backed by the NRF.
func NewNRFResolver(d Discoverer) *NRFResolver {
	return &NRFResolver{nrf: d, now: time.Now, cache: map[string]cached{}}
}

// Resolve discovers the NF whose FQDN equals targetHost and serves the API of
// path's first segment, and returns its base URL.
func (r *NRFResolver) Resolve(ctx context.Context, targetHost, path string) (*url.URL, error) {
	svc := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)[0]
	nfType, ok := serviceNFType[strings.SplitN(svc, "-", 2)[0]]
	if !ok {
		return nil, fmt.Errorf("n32f: resolve: unknown service %q: %w", svc, ErrTargetNotFound)
	}
	host := strings.ToLower(targetHost)
	key := host + "|" + svc
	r.mu.Lock()
	if c, ok := r.cache[key]; ok && r.now().Before(c.exp) {
		u := c.u
		r.mu.Unlock()
		return &u, nil
	}
	r.mu.Unlock()

	res, err := r.nrf.Discover(ctx, nrf.DiscoveryQuery{
		TargetNFType: nfType, RequesterNFType: requesterNFType, ServiceNames: []string{svc},
	})
	if err != nil {
		return nil, fmt.Errorf("n32f: resolve: %w", err)
	}
	for _, p := range res.NFInstances {
		for _, s := range p.NFServices {
			if s.ServiceName != svc {
				continue
			}
			if !strings.EqualFold(p.FQDN, host) {
				continue
			}
			// SBA is always TLS: only https is accepted (CLAUDE.md).
			if scheme := strings.ToLower(s.Scheme); scheme != "" && scheme != "https" {
				return nil, fmt.Errorf("n32f: resolve: scheme %q of %s: %w", s.Scheme, host, ErrTargetNotFound)
			}
			scheme := "https"
			h := host
			for _, ep := range s.IPEndpoints {
				if ep.Port > 0 {
					h = host + ":" + strconv.Itoa(ep.Port)
					break
				}
			}
			u := url.URL{Scheme: scheme, Host: h}
			r.store(key, u)
			return &u, nil
		}
	}
	return nil, ErrTargetNotFound
}

func (r *NRFResolver) store(key string, u url.URL) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cache) >= maxResolveCache {
		clear(r.cache)
	}
	r.cache[key] = cached{u: u, exp: r.now().Add(resolveTTL)}
}
