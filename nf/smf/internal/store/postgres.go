package store

import (
	"context"
	"embed"
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
		return nil, fmt.Errorf("smf store: pgxpool.New: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("smf store: postgres ping: %w", err)
	}
	p := &Postgres{pool: pool}
	if err := p.migrate(ctx); err != nil {
		return nil, fmt.Errorf("smf store: migrate: %w", err)
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

func (p *Postgres) UpsertSession(ctx context.Context, ref string, s *SessionRecord) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO smf_sessions
		    (sm_context_ref, supi, dnn, ue_ip, ul_teid, seid, sst, sd)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (sm_context_ref) DO UPDATE SET
		    supi    = EXCLUDED.supi,
		    dnn     = EXCLUDED.dnn,
		    ue_ip   = EXCLUDED.ue_ip,
		    ul_teid = EXCLUDED.ul_teid,
		    seid    = EXCLUDED.seid,
		    sst     = EXCLUDED.sst,
		    sd      = EXCLUDED.sd`,
		ref, s.SUPI, s.DNN, s.UEIP, s.ULTEID, s.SEID, s.SST, s.SD,
	)
	if err != nil {
		return fmt.Errorf("smf store: UpsertSession %s: %w", ref, err)
	}
	return nil
}

func (p *Postgres) DeleteSession(ctx context.Context, ref string) error {
	_, err := p.pool.Exec(ctx,
		`DELETE FROM smf_sessions WHERE sm_context_ref = $1`, ref)
	if err != nil {
		return fmt.Errorf("smf store: DeleteSession %s: %w", ref, err)
	}
	return nil
}

func (p *Postgres) ListSessions(ctx context.Context) (map[string]*SessionRecord, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT sm_context_ref, supi, dnn, ue_ip, ul_teid, seid, sst, sd
		FROM smf_sessions`)
	if err != nil {
		return nil, fmt.Errorf("smf store: ListSessions: %w", err)
	}
	defer rows.Close()
	result := make(map[string]*SessionRecord)
	for rows.Next() {
		var ref string
		var s SessionRecord
		if err := rows.Scan(&ref, &s.SUPI, &s.DNN, &s.UEIP, &s.ULTEID, &s.SEID, &s.SST, &s.SD); err != nil {
			return nil, fmt.Errorf("smf store: scan session: %w", err)
		}
		result[ref] = &s
	}
	return result, rows.Err()
}

func (p *Postgres) MaxCounters(ctx context.Context) (maxSEID uint64, maxTEID uint32, err error) {
	var seid *int64
	var teid *int64
	row := p.pool.QueryRow(ctx, `SELECT MAX(seid), MAX(ul_teid) FROM smf_sessions`)
	if scanErr := row.Scan(&seid, &teid); scanErr != nil {
		if !errors.Is(scanErr, pgx.ErrNoRows) {
			return 0, 0, fmt.Errorf("smf store: MaxCounters: %w", scanErr)
		}
	}
	if seid != nil {
		maxSEID = uint64(*seid)
	}
	if teid != nil {
		maxTEID = uint32(*teid)
	}
	return maxSEID, maxTEID, nil
}
