package store

// postgres_slice_dnn_qos.go — Postgres implementation of the slice_dnn_qos
// methods of Store (UDR-003). Row transitions are the shared pure functions in
// slice_dnn_qos.go, executed under SELECT ... FOR UPDATE so a seed and a portal
// edit cannot interleave: a seed never overwrites an edited row.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

const sliceQoSCols = `sst, sd, dnn, session_ambr_ul, session_ambr_dl, source,
	seed_ambr_ul, seed_ambr_dl, seed_source, updated_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanSliceQoS(r rowScanner) (SliceDNNQoS, error) {
	var q SliceDNNQoS
	var sst int16
	err := r.Scan(&sst, &q.SD, &q.DNN, &q.SessionAMBR.Uplink, &q.SessionAMBR.Downlink, &q.Source,
		&q.SeedAMBR.Uplink, &q.SeedAMBR.Downlink, &q.SeedSource, &q.UpdatedAt)
	q.SST = uint8(sst)
	return q, err
}

func (p *Postgres) ListSliceDNNQoS(ctx context.Context) ([]SliceDNNQoS, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+sliceQoSCols+` FROM slice_dnn_qos ORDER BY sst, sd, dnn`)
	if err != nil {
		return nil, fmt.Errorf("udr: ListSliceDNNQoS: %w", err)
	}
	defer rows.Close()
	out := []SliceDNNQoS{}
	for rows.Next() {
		q, err := scanSliceQoS(rows)
		if err != nil {
			return nil, fmt.Errorf("udr: ListSliceDNNQoS scan: %w", err)
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

func (p *Postgres) GetSliceDNNQoS(ctx context.Context, sst uint8, sd, dnn string) (*SliceDNNQoS, error) {
	k := NewSliceKey(sst, sd, dnn)
	q, err := scanSliceQoS(p.pool.QueryRow(ctx,
		`SELECT `+sliceQoSCols+` FROM slice_dnn_qos WHERE sst=$1 AND sd=$2 AND dnn=$3`, int16(k.SST), k.SD, k.DNN))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("udr: GetSliceDNNQoS: %w", err)
	}
	return &q, nil
}

// lockSliceQoS reads the row FOR UPDATE inside tx; nil when absent.
func lockSliceQoS(ctx context.Context, tx pgx.Tx, k SliceKey) (*SliceDNNQoS, error) {
	q, err := scanSliceQoS(tx.QueryRow(ctx,
		`SELECT `+sliceQoSCols+` FROM slice_dnn_qos WHERE sst=$1 AND sd=$2 AND dnn=$3 FOR UPDATE`,
		int16(k.SST), k.SD, k.DNN))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &q, nil
}

func upsertSliceQoS(ctx context.Context, tx pgx.Tx, q SliceDNNQoS) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO slice_dnn_qos (`+sliceQoSCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (sst, sd, dnn) DO UPDATE SET
		    session_ambr_ul = EXCLUDED.session_ambr_ul,
		    session_ambr_dl = EXCLUDED.session_ambr_dl,
		    source          = EXCLUDED.source,
		    seed_ambr_ul    = EXCLUDED.seed_ambr_ul,
		    seed_ambr_dl    = EXCLUDED.seed_ambr_dl,
		    seed_source     = EXCLUDED.seed_source,
		    updated_at      = EXCLUDED.updated_at`,
		int16(q.SST), q.SD, q.DNN, q.SessionAMBR.Uplink, q.SessionAMBR.Downlink, q.Source,
		q.SeedAMBR.Uplink, q.SeedAMBR.Downlink, q.SeedSource, q.UpdatedAt)
	return err
}

func (p *Postgres) PutSliceDNNQoSEdited(ctx context.Context, sst uint8, sd, dnn string, ambr AMBR, seed SliceDNNQoS) (created, changed bool, err error) {
	k := NewSliceKey(sst, sd, dnn)
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return false, false, fmt.Errorf("udr: PutSliceDNNQoSEdited: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	cur, err := lockSliceQoS(ctx, tx, k)
	if err != nil {
		return false, false, fmt.Errorf("udr: PutSliceDNNQoSEdited: %w", err)
	}
	next, created, changed := applyEdit(cur, k, ambr, seed, time.Now().UTC())
	if err := upsertSliceQoS(ctx, tx, next); err != nil {
		return false, false, fmt.Errorf("udr: PutSliceDNNQoSEdited: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, false, fmt.Errorf("udr: PutSliceDNNQoSEdited commit: %w", err)
	}
	return created, changed, nil
}

func (p *Postgres) RevertSliceDNNQoS(ctx context.Context, sst uint8, sd, dnn string) (*SliceDNNQoS, bool, error) {
	k := NewSliceKey(sst, sd, dnn)
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("udr: RevertSliceDNNQoS: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	cur, err := lockSliceQoS(ctx, tx, k)
	if err != nil {
		return nil, false, fmt.Errorf("udr: RevertSliceDNNQoS: %w", err)
	}
	if cur == nil {
		return nil, false, ErrNotFound
	}
	next, changed := applyRevert(*cur, time.Now().UTC())
	if changed {
		if err := upsertSliceQoS(ctx, tx, next); err != nil {
			return nil, false, fmt.Errorf("udr: RevertSliceDNNQoS: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf("udr: RevertSliceDNNQoS commit: %w", err)
	}
	return &next, changed, nil
}

// seedSliceQoSSQL is the seed-only upsert. Unlike upsertSliceQoS it carries the
// guard of design step A4: when the stored row is source='edited' the effective
// session_ambr_* and source are kept (a concurrent seed from another UDR instance
// or a restart can never overwrite an edit, even when SELECT ... FOR UPDATE
// locked nothing because the row did not exist yet); seed_* is always refreshed.
// RETURNING reports the row actually stored and whether it was inserted.
const seedSliceQoSSQL = `
	INSERT INTO slice_dnn_qos (` + sliceQoSCols + `)
	VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
	ON CONFLICT (sst, sd, dnn) DO UPDATE SET
	    session_ambr_ul = CASE WHEN slice_dnn_qos.source = 'edited' THEN slice_dnn_qos.session_ambr_ul ELSE EXCLUDED.session_ambr_ul END,
	    session_ambr_dl = CASE WHEN slice_dnn_qos.source = 'edited' THEN slice_dnn_qos.session_ambr_dl ELSE EXCLUDED.session_ambr_dl END,
	    source          = CASE WHEN slice_dnn_qos.source = 'edited' THEN slice_dnn_qos.source ELSE EXCLUDED.source END,
	    seed_ambr_ul    = EXCLUDED.seed_ambr_ul,
	    seed_ambr_dl    = EXCLUDED.seed_ambr_dl,
	    seed_source     = EXCLUDED.seed_source,
	    updated_at      = CASE WHEN slice_dnn_qos.source = 'edited'
	                            AND slice_dnn_qos.seed_ambr_ul = EXCLUDED.seed_ambr_ul
	                            AND slice_dnn_qos.seed_ambr_dl = EXCLUDED.seed_ambr_dl
	                            AND slice_dnn_qos.seed_source  = EXCLUDED.seed_source
	                       THEN slice_dnn_qos.updated_at ELSE EXCLUDED.updated_at END
	RETURNING ` + sliceQoSCols + `, (xmax = 0) AS inserted`

func (p *Postgres) SeedSliceDNNQoS(ctx context.Context, rows []SliceDNNQoS) (SeedCounts, error) {
	var c SeedCounts
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return c, fmt.Errorf("udr: SeedSliceDNNQoS: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := time.Now().UTC()
	for _, seed := range rows {
		k := NewSliceKey(seed.SST, seed.SD, seed.DNN)
		seed.SST, seed.SD, seed.DNN = k.SST, k.SD, k.DNN
		// Pre-image (locks the row when it exists); nil when absent.
		cur, err := lockSliceQoS(ctx, tx, k)
		if err != nil {
			return c, fmt.Errorf("udr: SeedSliceDNNQoS: %w", err)
		}
		next, out, changed := applySeed(cur, seed, now)
		if out == seedUnchanged {
			c.add(k, out, changed)
			continue
		}
		var inserted bool
		stored, err := scanSeeded(tx.QueryRow(ctx, seedSliceQoSSQL,
			int16(k.SST), k.SD, k.DNN, next.SessionAMBR.Uplink, next.SessionAMBR.Downlink, next.Source,
			next.SeedAMBR.Uplink, next.SeedAMBR.Downlink, next.SeedSource, next.UpdatedAt), &inserted)
		if err != nil {
			return c, fmt.Errorf("udr: SeedSliceDNNQoS: %w", err)
		}
		if cur == nil && !inserted {
			// Lost the insert race: a concurrent writer created the row after our
			// pre-read. The guarded upsert preserved an edit; report what is stored.
			if stored.Source == SourceEdited {
				out, changed = seedEditedKept, false
			} else {
				out, changed = seedRefreshed, stored.SessionAMBR != DefaultAMBRForSlice(k.SST, k.SD)
			}
		}
		c.add(k, out, changed)
	}
	if err := tx.Commit(ctx); err != nil {
		return SeedCounts{}, fmt.Errorf("udr: SeedSliceDNNQoS commit: %w", err)
	}
	return c, nil
}

// scanSeeded scans a seedSliceQoSSQL RETURNING row.
func scanSeeded(r rowScanner, inserted *bool) (SliceDNNQoS, error) {
	var q SliceDNNQoS
	var sst int16
	err := r.Scan(&sst, &q.SD, &q.DNN, &q.SessionAMBR.Uplink, &q.SessionAMBR.Downlink, &q.Source,
		&q.SeedAMBR.Uplink, &q.SeedAMBR.Downlink, &q.SeedSource, &q.UpdatedAt, inserted)
	q.SST = uint8(sst)
	return q, err
}

func (p *Postgres) ListSUPIsForSliceDNN(ctx context.Context, sst uint8, sd, dnn string) ([]string, error) {
	k := NewSliceKey(sst, sd, dnn)
	filter, err := json.Marshal([]map[string]any{{"sst": k.SST}})
	if err != nil {
		return nil, err
	}
	rows, err := p.pool.Query(ctx,
		`SELECT supi, snssais FROM subscription_am WHERE snssais @> $1::jsonb ORDER BY supi`, string(filter))
	if err != nil {
		return nil, fmt.Errorf("udr: ListSUPIsForSliceDNN: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var supi string
		var raw []byte
		if err := rows.Scan(&supi, &raw); err != nil {
			return nil, fmt.Errorf("udr: ListSUPIsForSliceDNN scan: %w", err)
		}
		var ns []SNSSAISubscribed
		if err := json.Unmarshal(raw, &ns); err != nil {
			return nil, fmt.Errorf("udr: ListSUPIsForSliceDNN: unmarshal snssais of %s: %w", supi, err)
		}
		for _, n := range ns {
			if sliceKeyOf(n) == k {
				out = append(out, supi)
				break
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

func (p *Postgres) ListSliceKeysInUse(ctx context.Context) ([]SliceKey, error) {
	rows, err := p.pool.Query(ctx, `SELECT snssais FROM subscription_am`)
	if err != nil {
		return nil, fmt.Errorf("udr: ListSliceKeysInUse: %w", err)
	}
	defer rows.Close()
	set := make(map[SliceKey]struct{})
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("udr: ListSliceKeysInUse scan: %w", err)
		}
		var ns []SNSSAISubscribed
		if err := json.Unmarshal(raw, &ns); err != nil {
			return nil, fmt.Errorf("udr: ListSliceKeysInUse: unmarshal snssais: %w", err)
		}
		for _, n := range ns {
			set[sliceKeyOf(n)] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return sortedKeys(set), nil
}

var _ Store = (*Postgres)(nil)
var _ Store = (*InMemory)(nil)
