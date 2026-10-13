package clients

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"time"

	promclient "github.com/francurieses/claudia-5gc/mcp/internal/prometheus"
)

// instanceRe is the accepted shape of a Prometheus instance label: host:port.
var instanceRe = regexp.MustCompile(`^[A-Za-z0-9.-]+:[0-9]{2,5}$`)

// hostRe is the accepted shape of a metrics host override.
var hostRe = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)

// nfLabelValueRe bounds the NF name placed inside a PromQL label matcher.
var nfLabelValueRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,31}$`)

// ErrNoTarget is returned by Targets.Addr when no valid scrape target exists for the NF.
var ErrNoTarget = errors.New("no Prometheus scrape target")

// Target is one Prometheus scrape target of the NF job (up{nf=...}).
type Target struct {
	// NF is the value of the nf label.
	NF string
	// Instance is the metrics address host:port with the host override applied.
	// It is empty when the Prometheus instance label is not a valid host:port.
	Instance string
	// Raw is the instance label exactly as Prometheus reports it.
	Raw string
	// Up is the scrape state.
	Up bool
}

// Targets resolves NF metrics addresses from Prometheus scrape targets. When the
// MCP server runs on the host instead of the Docker network, Prometheus reports
// container names (smf:9105) that do not resolve; the host override swaps the host
// part for a reachable one (localhost) and keeps the published port.
type Targets struct {
	prom         *promclient.Client
	hostOverride string
}

// NewTargets builds a resolver over a Prometheus client. hostOverride may be empty
// (addresses unchanged); a value that is not a plain host name or IP is ignored.
func NewTargets(prom *promclient.Client, hostOverride string) *Targets {
	if !hostRe.MatchString(hostOverride) {
		hostOverride = ""
	}
	return &Targets{prom: prom, hostOverride: hostOverride}
}

// Resolve applies the host override to one instance label and validates it. It
// returns "" when the instance is not host:port.
func (t *Targets) Resolve(instance string) string {
	if !instanceRe.MatchString(instance) {
		return ""
	}
	if t.hostOverride == "" {
		return instance
	}
	_, port, err := net.SplitHostPort(instance)
	if err != nil {
		return ""
	}
	return net.JoinHostPort(t.hostOverride, port)
}

// List returns every scrape target that carries an nf label.
func (t *Targets) List(ctx context.Context) ([]Target, error) {
	return t.query(ctx, `up{nf=~".+"}`)
}

// Addr returns the metrics address host:port of one NF, after the host override.
func (t *Targets) Addr(ctx context.Context, nf string) (string, error) {
	if !nfLabelValueRe.MatchString(nf) {
		return "", fmt.Errorf("targets: invalid NF name %q", nf)
	}
	targets, err := t.query(ctx, `up{nf="`+nf+`"}`)
	if err != nil {
		return "", err
	}
	for _, tg := range targets {
		if tg.Instance != "" {
			return tg.Instance, nil
		}
	}
	return "", fmt.Errorf("targets: %s: %w", nf, ErrNoTarget)
}

func (t *Targets) query(ctx context.Context, q string) ([]Target, error) {
	res, err := t.prom.Query(ctx, q, time.Time{})
	if err != nil {
		return nil, fmt.Errorf("targets: query prometheus: %w", err)
	}
	out := make([]Target, 0, len(res.Data.Result))
	for _, s := range res.Data.Result {
		raw := s.Metric["instance"]
		out = append(out, Target{
			NF:       s.Metric["nf"],
			Instance: t.Resolve(raw),
			Raw:      raw,
			Up:       s.Float64() == 1,
		})
	}
	return out, nil
}
