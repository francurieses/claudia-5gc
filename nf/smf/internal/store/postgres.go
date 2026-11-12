package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"

	"github.com/francurieses/claudia-5gc/shared/dbmigrate"
	"github.com/francurieses/claudia-5gc/shared/jsoncompat"
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
	return dbmigrate.Run(ctx, dbmigrate.PgxDB{Pool: p.pool}, "smf", migrationsFS, "migrations", slog.Default())
}

func (p *Postgres) Close() { p.pool.Close() }

func (p *Postgres) UpsertSession(ctx context.Context, ref string, s *SessionRecord) error {
	extra, err := encodeExtra(s.Extra)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `
		INSERT INTO smf_sessions
		    (sm_context_ref, supi, dnn, ue_ip, ul_teid, seid, sst, sd, pdu_session_id,
		     schema_version, extra)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (sm_context_ref) DO UPDATE SET
		    supi    = EXCLUDED.supi,
		    dnn     = EXCLUDED.dnn,
		    ue_ip   = EXCLUDED.ue_ip,
		    ul_teid = EXCLUDED.ul_teid,
		    seid    = EXCLUDED.seid,
		    sst     = EXCLUDED.sst,
		    sd      = EXCLUDED.sd,
		    pdu_session_id = EXCLUDED.pdu_session_id,
		    schema_version = EXCLUDED.schema_version,
		    extra          = EXCLUDED.extra`,
		ref, s.SUPI, s.DNN, s.UEIP, s.ULTEID, s.SEID, s.SST, s.SD, int(s.PSI),
		jsoncompat.NextVersion(s.SchemaVersion, SessionSchemaVersion), extra,
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
		SELECT sm_context_ref, supi, dnn, ue_ip, ul_teid, seid, sst, sd, pdu_session_id,
		       schema_version, extra
		FROM smf_sessions`)
	if err != nil {
		return nil, fmt.Errorf("smf store: ListSessions: %w", err)
	}
	defer rows.Close()
	result := make(map[string]*SessionRecord)
	for rows.Next() {
		var ref string
		var s SessionRecord
		var psi int
		var extra []byte
		if err := rows.Scan(&ref, &s.SUPI, &s.DNN, &s.UEIP, &s.ULTEID, &s.SEID, &s.SST, &s.SD, &psi,
			&s.SchemaVersion, &extra); err != nil {
			return nil, fmt.Errorf("smf store: scan session: %w", err)
		}
		if s.Extra, err = decodeExtra(extra); err != nil {
			return nil, err
		}
		s.PSI = uint8(psi)
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
		maxSEID = uint64(*seid) //nolint:gosec // SEID is stored as bigint; the uint64 bit pattern round-trips
	}
	if teid != nil {
		maxTEID = uint32(*teid) //nolint:gosec // TEID is stored as bigint holding a uint32
	}
	return maxSEID, maxTEID, nil
}
