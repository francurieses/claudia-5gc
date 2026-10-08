package store

// slice_dnn_qos.go — per (S-NSSAI, DNN) subscribed Session-AMBR (UDR-003).
//
// The subscribed Session-AMBR is a subscription parameter retrieved by the SMF
// from the UDM (TS 23.501 §5.7.2.6) and carried in
// SessionManagementSubscriptionData.dnnConfigurations{dnn}.sessionAmbr
// (TS 29.503 §6.1.6.2.8 / §6.1.6.2.9). The values live in the slice_dnn_qos
// table (PostgreSQL) or an in-memory map; DefaultAMBRForSlice is only the seed
// and fallback default. The table is a NON-3GPP management store.

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/francurieses/claudia-5gc/nf/udr/internal/qos"
	operatorcfg "github.com/francurieses/claudia-5gc/shared/config"
)

// Origin of a slice_dnn_qos value.
const (
	// SourceDefault means the value comes from DefaultAMBRForSlice.
	SourceDefault = "default"
	// SourceOperator means the value comes from operator.yaml slice_dnn_qos.
	SourceOperator = "operator"
	// SourceEdited means the value was set through the internal API / portal.
	SourceEdited = "edited"
)

// DefaultDNN is the DNN assumed for an S-NSSAI whose am-data entry carries no
// DNN (same rule as BuildSMSubscriptions).
const DefaultDNN = "internet"

// SliceKey identifies a slice_dnn_qos row. SD is lower-case hex or "" (no SD);
// DNN is lower-cased (DNN comparison is case-insensitive, TS 23.003 §9.1).
type SliceKey struct {
	SST uint8
	SD  string
	DNN string
}

// NewSliceKey builds a normalised SliceKey (lower-case SD, lower-case DNN).
func NewSliceKey(sst uint8, sd, dnn string) SliceKey {
	return SliceKey{SST: sst, SD: strings.ToLower(strings.TrimSpace(sd)), DNN: strings.ToLower(strings.TrimSpace(dnn))}
}

// String renders the key as "sst/sd/dnn" ("-" for no SD), the API path form.
func (k SliceKey) String() string {
	sd := k.SD
	if sd == "" {
		sd = "-"
	}
	return fmt.Sprintf("%d/%s/%s", k.SST, sd, k.DNN)
}

// SliceDNNQoS is one slice_dnn_qos row: the effective subscribed Session-AMBR of
// an (S-NSSAI, DNN) pair plus the seed value that a revert restores.
type SliceDNNQoS struct {
	SST         uint8
	SD          string
	DNN         string
	SessionAMBR AMBR   // effective value
	Source      string // SourceDefault | SourceOperator | SourceEdited
	SeedAMBR    AMBR   // value the seed produces
	SeedSource  string // SourceDefault | SourceOperator
	UpdatedAt   time.Time
}

// Key returns the row's SliceKey.
func (q SliceDNNQoS) Key() SliceKey { return SliceKey{SST: q.SST, SD: q.SD, DNN: q.DNN} }

// DefaultSliceDNNQoS returns the seed row for a key when operator.yaml has no
// entry: DefaultAMBRForSlice, source=default.
func DefaultSliceDNNQoS(k SliceKey) SliceDNNQoS {
	a := DefaultAMBRForSlice(k.SST, k.SD)
	return SliceDNNQoS{SST: k.SST, SD: k.SD, DNN: k.DNN, SessionAMBR: a, Source: SourceDefault, SeedAMBR: a, SeedSource: SourceDefault}
}

// SessionAMBRFunc resolves the subscribed Session-AMBR for (sst, sd, dnn).
type SessionAMBRFunc func(sst uint8, sd, dnn string) AMBR

// SessionAMBRResolver snapshots slice_dnn_qos (one list query) and returns a
// resolver that falls back to DefaultAMBRForSlice for keys with no row.
func SessionAMBRResolver(ctx context.Context, s Store) (SessionAMBRFunc, error) {
	rows, err := s.ListSliceDNNQoS(ctx)
	if err != nil {
		return nil, fmt.Errorf("udr: session ambr resolver: %w", err)
	}
	m := make(map[SliceKey]AMBR, len(rows))
	for _, r := range rows {
		m[r.Key()] = r.SessionAMBR
	}
	return func(sst uint8, sd, dnn string) AMBR {
		if a, ok := m[NewSliceKey(sst, sd, dnn)]; ok {
			return a
		}
		return DefaultAMBRForSlice(sst, sd)
	}, nil
}

// ---- pure row transitions (shared by InMemory and Postgres) ---------------

// applyEdit returns the row after a portal/API edit. cur is nil for a new row.
func applyEdit(cur *SliceDNNQoS, k SliceKey, ambr AMBR, seed SliceDNNQoS, now time.Time) (next SliceDNNQoS, created, changed bool) {
	if cur == nil {
		return SliceDNNQoS{SST: k.SST, SD: k.SD, DNN: k.DNN, SessionAMBR: ambr, Source: SourceEdited,
			SeedAMBR: seed.SeedAMBR, SeedSource: seed.SeedSource, UpdatedAt: now}, true, true
	}
	next = *cur
	changed = cur.SessionAMBR != ambr || cur.Source != SourceEdited
	next.SessionAMBR, next.Source = ambr, SourceEdited
	if changed {
		next.UpdatedAt = now
	}
	return next, false, changed
}

// applyRevert restores the seed value; changed is true only for an edited row.
func applyRevert(cur SliceDNNQoS, now time.Time) (next SliceDNNQoS, changed bool) {
	next = cur
	if cur.Source != SourceEdited {
		return next, false
	}
	next.SessionAMBR, next.Source, next.UpdatedAt = cur.SeedAMBR, cur.SeedSource, now
	return next, true
}

type seedOutcome int

const (
	seedInserted seedOutcome = iota
	seedRefreshed
	seedEditedKept
	seedUnchanged
)

// applySeed merges a seed row (SessionAMBR/Source = seed value) into cur. The
// effective value of an edited row is never overwritten; seed_* always is.
// changed reports a change of the effective value that sm-data must reflect.
func applySeed(cur *SliceDNNQoS, seed SliceDNNQoS, now time.Time) (next SliceDNNQoS, out seedOutcome, changed bool) {
	k := seed.Key()
	if cur == nil {
		next = SliceDNNQoS{SST: k.SST, SD: k.SD, DNN: k.DNN, SessionAMBR: seed.SessionAMBR, Source: seed.Source,
			SeedAMBR: seed.SessionAMBR, SeedSource: seed.Source, UpdatedAt: now}
		// Existing subscribers were built with the fallback default.
		return next, seedInserted, seed.SessionAMBR != DefaultAMBRForSlice(k.SST, k.SD)
	}
	next = *cur
	seedChanged := cur.SeedAMBR != seed.SessionAMBR || cur.SeedSource != seed.Source
	next.SeedAMBR, next.SeedSource = seed.SessionAMBR, seed.Source
	if cur.Source == SourceEdited {
		if seedChanged {
			next.UpdatedAt = now
		}
		return next, seedEditedKept, false
	}
	changed = cur.SessionAMBR != seed.SessionAMBR
	next.SessionAMBR, next.Source = seed.SessionAMBR, seed.Source
	if changed || seedChanged || cur.Source != seed.Source {
		next.UpdatedAt = now
	}
	if changed || seedChanged || cur.Source != seed.Source {
		return next, seedRefreshed, changed
	}
	return next, seedUnchanged, false
}

func sortQoS(rows []SliceDNNQoS) {
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.SST != b.SST {
			return a.SST < b.SST
		}
		if a.SD != b.SD {
			return a.SD < b.SD
		}
		return a.DNN < b.DNN
	})
}

// ---- InMemory implementation ---------------------------------------------

func (s *InMemory) ListSliceDNNQoS(_ context.Context) ([]SliceDNNQoS, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SliceDNNQoS, 0, len(s.sliceQoS))
	for _, r := range s.sliceQoS {
		out = append(out, r)
	}
	sortQoS(out)
	return out, nil
}

func (s *InMemory) GetSliceDNNQoS(_ context.Context, sst uint8, sd, dnn string) (*SliceDNNQoS, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.sliceQoS[NewSliceKey(sst, sd, dnn)]
	if !ok {
		return nil, nil
	}
	return &r, nil
}

func (s *InMemory) PutSliceDNNQoSEdited(_ context.Context, sst uint8, sd, dnn string, ambr AMBR, seed SliceDNNQoS) (created, changed bool, err error) {
	k := NewSliceKey(sst, sd, dnn)
	s.mu.Lock()
	defer s.mu.Unlock()
	var cur *SliceDNNQoS
	if r, ok := s.sliceQoS[k]; ok {
		cur = &r
	}
	next, created, changed := applyEdit(cur, k, ambr, seed, time.Now().UTC())
	s.sliceQoS[k] = next
	return created, changed, nil
}

func (s *InMemory) RevertSliceDNNQoS(_ context.Context, sst uint8, sd, dnn string) (*SliceDNNQoS, bool, error) {
	k := NewSliceKey(sst, sd, dnn)
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.sliceQoS[k]
	if !ok {
		return nil, false, ErrNotFound
	}
	next, changed := applyRevert(cur, time.Now().UTC())
	s.sliceQoS[k] = next
	return &next, changed, nil
}

func (s *InMemory) SeedSliceDNNQoS(_ context.Context, rows []SliceDNNQoS) (SeedCounts, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var c SeedCounts
	now := time.Now().UTC()
	for _, seed := range rows {
		k := NewSliceKey(seed.SST, seed.SD, seed.DNN)
		seed.SST, seed.SD, seed.DNN = k.SST, k.SD, k.DNN
		var cur *SliceDNNQoS
		if r, ok := s.sliceQoS[k]; ok {
			cur = &r
		}
		next, out, changed := applySeed(cur, seed, now)
		s.sliceQoS[k] = next
		c.add(k, out, changed)
	}
	return c, nil
}

func (s *InMemory) ListSUPIsForSliceDNN(_ context.Context, sst uint8, sd, dnn string) ([]string, error) {
	k := NewSliceKey(sst, sd, dnn)
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for supi, am := range s.amSubs {
		for _, n := range am.NSSAI.SNSSAIs {
			if sliceKeyOf(n) == k {
				out = append(out, supi)
				break
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s *InMemory) ListSliceKeysInUse(_ context.Context) ([]SliceKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	set := make(map[SliceKey]struct{})
	for _, am := range s.amSubs {
		for _, n := range am.NSSAI.SNSSAIs {
			set[sliceKeyOf(n)] = struct{}{}
		}
	}
	return sortedKeys(set), nil
}

// sliceKeyOf applies the effective-DNN rule of BuildSMSubscriptions.
func sliceKeyOf(n SNSSAISubscribed) SliceKey {
	dnn := n.DNN
	if dnn == "" {
		dnn = DefaultDNN
	}
	return NewSliceKey(n.SST, n.SD, dnn)
}

func sortedKeys(set map[SliceKey]struct{}) []SliceKey {
	out := make([]SliceKey, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.SST != b.SST {
			return a.SST < b.SST
		}
		if a.SD != b.SD {
			return a.SD < b.SD
		}
		return a.DNN < b.DNN
	})
	return out
}

// ---- seed ------------------------------------------------------------------

// SeedCounts is the per-call outcome of Store.SeedSliceDNNQoS.
type SeedCounts struct {
	Inserted    int
	Refreshed   int
	EditedKept  int
	Unchanged   int
	ChangedKeys []SliceKey // effective value changed: sm-data of these keys is stale
}

func (c *SeedCounts) add(k SliceKey, out seedOutcome, changed bool) {
	switch out {
	case seedInserted:
		c.Inserted++
	case seedRefreshed:
		c.Refreshed++
	case seedEditedKept:
		c.EditedKept++
	default:
		c.Unchanged++
	}
	if changed {
		c.ChangedKeys = append(c.ChangedKeys, k)
	}
}

// OperatorSeedEntry is a validated operator.yaml slice_dnn_qos entry.
type OperatorSeedEntry struct {
	Key  SliceKey
	AMBR AMBR
}

// SeedResult summarises a seed run.
type SeedResult struct {
	SeedCounts
	Resynced int // subscribers re-derived (SeedAndResyncSliceDNNQoS only)
}

// defaultOperatorSlices is the fallback slice set when operator.yaml is absent
// (identical to the fallback in cmd/udr/main.go).
var defaultOperatorSlices = []SNSSAISubscribed{
	{SST: 1, SD: "000001"}, {SST: 1, SD: "000002"}, {SST: 2, SD: "000001"}, {SST: 3, SD: "000001"},
}

// OperatorSeedEntries validates op.SliceDNNQoSList(): each entry needs sst
// 0-255, sd "" or 6 hex, a DNN, a slice listed in op.snssais (when that list is
// non-empty) and two valid TS 29.571 BitRates. Invalid entries are skipped with
// a WARN and fall back to DefaultAMBRForSlice.
func OperatorSeedEntries(op *operatorcfg.OperatorConfig, logger *slog.Logger) []OperatorSeedEntry {
	if logger == nil {
		logger = slog.Default()
	}
	slices := op.Slices()
	var out []OperatorSeedEntry
	for _, e := range op.SliceDNNQoSList() {
		warn := func(reason string) {
			logger.Warn("slice_dnn_qos entry ignored",
				"procedure", "SliceSessionAmbrConfig", "interface", "Nudr-internal",
				"direction", "IN", "spec_ref", "TS 23.501 §5.7.2.6",
				"sst", e.SST, "sd", e.SD, "dnn", e.DNN, "result", "REJECT", "cause", reason)
		}
		if e.SST < 0 || e.SST > 255 {
			warn("sst out of range")
			continue
		}
		sd := strings.ToLower(e.SD)
		if !ValidSD(sd) {
			warn("sd must be empty or six hex digits")
			continue
		}
		dnn := strings.TrimSpace(e.DNN)
		if dnn == "" {
			warn("dnn missing")
			continue
		}
		if len(slices) > 0 {
			found := false
			for _, s := range slices {
				if s.SST == e.SST && strings.EqualFold(s.SD, sd) {
					found = true
					break
				}
			}
			if !found {
				warn("slice not in operator snssais")
				continue
			}
		}
		ul, _, err := qos.ValidateBitRate(e.SessionAMBR.Uplink)
		if err != nil {
			warn("uplink: " + err.Error())
			continue
		}
		dl, _, err := qos.ValidateBitRate(e.SessionAMBR.Downlink)
		if err != nil {
			warn("downlink: " + err.Error())
			continue
		}
		out = append(out, OperatorSeedEntry{Key: NewSliceKey(uint8(e.SST), sd, dnn), AMBR: AMBR{Uplink: ul, Downlink: dl}})
	}
	return out
}

// ValidSD reports whether sd is "" (no SD) or six lower/upper-case hex digits.
func ValidSD(sd string) bool {
	if sd == "" {
		return true
	}
	if len(sd) != 6 {
		return false
	}
	for _, c := range sd {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// SeedSliceDNNQoSFromEntries builds the seed set and applies it. Seed set:
// every slice in slices x its DNN (default "internet"), every key already used
// in subscription_am, and every operator entry (which wins over the default).
// Edited rows keep their effective value; seed_* is always refreshed.
func SeedSliceDNNQoSFromEntries(ctx context.Context, st Store, slices []SNSSAISubscribed, entries []OperatorSeedEntry) (*SeedResult, error) {
	keys := make(map[SliceKey]struct{})
	for _, n := range slices {
		keys[sliceKeyOf(n)] = struct{}{}
	}
	inUse, err := st.ListSliceKeysInUse(ctx)
	if err != nil {
		return nil, fmt.Errorf("udr: seed slice_dnn_qos: %w", err)
	}
	for _, k := range inUse {
		keys[k] = struct{}{}
	}
	byKey := make(map[SliceKey]AMBR, len(entries))
	for _, e := range entries {
		k := NewSliceKey(e.Key.SST, e.Key.SD, e.Key.DNN)
		byKey[k] = e.AMBR
		keys[k] = struct{}{}
	}
	rows := make([]SliceDNNQoS, 0, len(keys))
	for _, k := range sortedKeys(keys) {
		row := DefaultSliceDNNQoS(k)
		if a, ok := byKey[k]; ok {
			row.SessionAMBR, row.Source = a, SourceOperator
		}
		rows = append(rows, row)
	}
	c, err := st.SeedSliceDNNQoS(ctx, rows)
	if err != nil {
		return nil, fmt.Errorf("udr: seed slice_dnn_qos: %w", err)
	}
	return &SeedResult{SeedCounts: c}, nil
}

// SeedSliceDNNQoSFromOperator seeds slice_dnn_qos from operator.yaml (op may be
// nil: default 4-slice set x "internet" with DefaultAMBRForSlice).
func SeedSliceDNNQoSFromOperator(ctx context.Context, st Store, op *operatorcfg.OperatorConfig, logger *slog.Logger) (*SeedResult, error) {
	slices := defaultOperatorSlices
	if s := op.Slices(); len(s) > 0 {
		slices = make([]SNSSAISubscribed, 0, len(s))
		for _, e := range s {
			slices = append(slices, SNSSAISubscribed{SST: uint8(e.SST), SD: e.SD})
		}
	}
	return SeedSliceDNNQoSFromEntries(ctx, st, slices, OperatorSeedEntries(op, logger))
}

// SeedAndResyncSliceDNNQoS seeds the table and re-derives sm-data of every
// subscriber on a key whose effective value changed (operator.yaml edited since
// the last start). Logs one summary line.
func SeedAndResyncSliceDNNQoS(ctx context.Context, st Store, op *operatorcfg.OperatorConfig, logger *slog.Logger) (*SeedResult, error) {
	if logger == nil {
		logger = slog.Default()
	}
	start := time.Now()
	res, err := SeedSliceDNNQoSFromOperator(ctx, st, op, logger)
	if err != nil {
		return nil, err
	}
	for _, k := range res.ChangedKeys {
		rr, err := ResyncSliceDNN(ctx, st, k)
		res.Resynced += rr.Synced
		if err != nil {
			logger.Warn("slice_dnn_qos seed resync failed", "procedure", "SliceSessionAmbrConfig",
				"interface", "Nudr-internal", "direction", "OUT", "spec_ref", "TS 29.503 §6.1.6.2.9",
				"sst", k.SST, "sd", k.SD, "dnn", k.DNN, "result", "FAILURE", "cause", err.Error())
		}
		for _, f := range rr.Failed {
			logger.Warn("slice_dnn_qos seed resync: subscriber failed",
				"procedure", "SliceSessionAmbrConfig", "interface", "Nudr-internal", "direction", "OUT",
				"spec_ref", "TS 29.503 §6.1.6.2.9", "supi", f.SUPI, "result", "FAILURE", "cause", f.Error)
		}
	}
	logger.Info("slice_dnn_qos seeded", "procedure", "SliceSessionAmbrConfig",
		"interface", "Nudr-internal", "direction", "OUT", "spec_ref", "TS 23.501 §5.7.2.6",
		"seeded", res.Inserted, "refreshed", res.Refreshed, "edited_kept", res.EditedKept,
		"unchanged", res.Unchanged, "resynced_subscribers", res.Resynced,
		"result", "OK", "duration_ms", time.Since(start).Milliseconds())
	return res, nil
}

// ---- resync ----------------------------------------------------------------

// ResyncFailure is one subscriber whose sm-data could not be re-derived.
type ResyncFailure struct {
	SUPI  string `json:"supi"`
	Error string `json:"error"`
}

// ResyncResult is the outcome of re-deriving sm-data for one slice/DNN.
type ResyncResult struct {
	Affected int
	Synced   int
	Failed   []ResyncFailure
}

// ResyncSliceDNN re-derives sm-data (SyncSMDataFromAMContext) of every
// subscriber whose am-data carries the key. Per-subscriber failures are
// collected in Failed; err is set only when the subscriber listing fails.
// It reads the table, never a request body, so concurrent edits converge.
func ResyncSliceDNN(ctx context.Context, st Store, k SliceKey) (ResyncResult, error) {
	supis, err := st.ListSUPIsForSliceDNN(ctx, k.SST, k.SD, k.DNN)
	if err != nil {
		return ResyncResult{}, fmt.Errorf("udr: resync slice %s: %w", k, err)
	}
	res := ResyncResult{Affected: len(supis), Failed: []ResyncFailure{}}
	for _, supi := range supis {
		if _, err := SyncSMDataFromAMContext(ctx, st, supi); err != nil {
			res.Failed = append(res.Failed, ResyncFailure{SUPI: supi, Error: err.Error()})
			continue
		}
		res.Synced++
	}
	return res, nil
}
