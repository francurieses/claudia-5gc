package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Postgres implements Store backed by PostgreSQL 16.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres opens a connection pool and runs embedded migrations.
func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("amf store: pgxpool.New: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("amf store: postgres ping: %w", err)
	}
	p := &Postgres{pool: pool}
	if err := p.migrate(ctx); err != nil {
		return nil, fmt.Errorf("amf store: migrate: %w", err)
	}
	return p, nil
}

func (p *Postgres) migrate(ctx context.Context) error {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	for _, e := range entries {
		sql, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return err
		}
		if _, err := p.pool.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("migration %s: %w", e.Name(), err)
		}
	}
	return nil
}

func (p *Postgres) Close() { p.pool.Close() }

func (p *Postgres) UpsertUE(ctx context.Context, rec *UERecord) error {
	js, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("amf store: marshal ue_context: %w", err)
	}
	var tmsi *uint32
	if rec.GUTI != nil {
		tmsi = &rec.GUTI.TMSI
	}
	_, err = p.pool.Exec(ctx, `
		INSERT INTO amf_ue_contexts
		    (supi, tmsi, gmm_state, context_json, registered_at, last_activity)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (supi) DO UPDATE SET
		    tmsi          = EXCLUDED.tmsi,
		    gmm_state     = EXCLUDED.gmm_state,
		    context_json  = EXCLUDED.context_json,
		    last_activity = EXCLUDED.last_activity`,
		rec.SUPI, tmsi, rec.GMMState, js,
		rec.RegistrationTime, rec.LastActivity,
	)
	if err != nil {
		return fmt.Errorf("amf store: UpsertUE %s: %w", rec.SUPI, err)
	}
	return nil
}

func (p *Postgres) GetUEBySUPI(ctx context.Context, supi string) (*UERecord, error) {
	var js []byte
	err := p.pool.QueryRow(ctx,
		`SELECT context_json FROM amf_ue_contexts WHERE supi = $1`, supi,
	).Scan(&js)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("amf store: GetUEBySUPI: %w", err)
	}
	return unmarshalRecord(js)
}

func (p *Postgres) GetUEByTMSI(ctx context.Context, tmsi uint32) (*UERecord, error) {
	var js []byte
	err := p.pool.QueryRow(ctx,
		`SELECT context_json FROM amf_ue_contexts WHERE tmsi = $1`, tmsi,
	).Scan(&js)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("amf store: GetUEByTMSI: %w", err)
	}
	return unmarshalRecord(js)
}

func (p *Postgres) DeleteUE(ctx context.Context, supi string) error {
	_, err := p.pool.Exec(ctx,
		`DELETE FROM amf_ue_contexts WHERE supi = $1`, supi)
	if err != nil {
		return fmt.Errorf("amf store: DeleteUE %s: %w", supi, err)
	}
	return nil
}

// PurgeAllUEContexts deletes every row from amf_ue_contexts.
// Called at AMF startup so stale contexts from previous runs do not linger.
func (p *Postgres) PurgeAllUEContexts(ctx context.Context) (int64, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM amf_ue_contexts`)
	if err != nil {
		return 0, fmt.Errorf("amf store: PurgeAllUEContexts: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (p *Postgres) ListRegisteredUEs(ctx context.Context) ([]*UERecord, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT context_json FROM amf_ue_contexts WHERE gmm_state = $1`,
		gmmStateRegistered,
	)
	if err != nil {
		return nil, fmt.Errorf("amf store: ListRegisteredUEs: %w", err)
	}
	defer rows.Close()
	var result []*UERecord
	for rows.Next() {
		var js []byte
		if err := rows.Scan(&js); err != nil {
			return nil, fmt.Errorf("amf store: scan: %w", err)
		}
		rec, err := unmarshalRecord(js)
		if err != nil {
			return nil, err
		}
		result = append(result, rec)
	}
	return result, rows.Err()
}

// ListAllUEContexts returns every persisted UE context, regardless of 5GMM
// state. Unlike ListRegisteredUEs it does not filter: it is used at startup to
// find the SM contexts that must be released at the SMF before the rows are
// purged, and a UE can still own PDU sessions while not in 5GMM-REGISTERED.
// Ref: TS 23.007 §16 (restoration of data in the AMF).
func (p *Postgres) ListAllUEContexts(ctx context.Context) ([]*UERecord, error) {
	rows, err := p.pool.Query(ctx, `SELECT context_json FROM amf_ue_contexts`)
	if err != nil {
		return nil, fmt.Errorf("amf store: ListAllUEContexts: %w", err)
	}
	defer rows.Close()
	var result []*UERecord
	for rows.Next() {
		var js []byte
		if err := rows.Scan(&js); err != nil {
			return nil, fmt.Errorf("amf store: scan: %w", err)
		}
		rec, err := unmarshalRecord(js)
		if err != nil {
			return nil, err
		}
		result = append(result, rec)
	}
	return result, rows.Err()
}

func (p *Postgres) MaxTMSI(ctx context.Context) (uint32, error) {
	var max *int64
	err := p.pool.QueryRow(ctx,
		`SELECT MAX(tmsi) FROM amf_ue_contexts`,
	).Scan(&max)
	if err != nil {
		return 0, fmt.Errorf("amf store: MaxTMSI: %w", err)
	}
	if max == nil {
		return 0, nil
	}
	return uint32(*max), nil
}

func unmarshalRecord(js []byte) (*UERecord, error) {
	var rec UERecord
	if err := json.Unmarshal(js, &rec); err != nil {
		return nil, fmt.Errorf("amf store: unmarshal ue_context: %w", err)
	}
	return &rec, nil
}
