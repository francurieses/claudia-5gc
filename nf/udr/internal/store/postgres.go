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
		return nil, fmt.Errorf("udr: pgxpool.New: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("udr: postgres ping: %w", err)
	}
	p := &Postgres{pool: pool}
	if err := p.migrate(ctx); err != nil {
		return nil, fmt.Errorf("udr: migrate: %w", err)
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

// Close shuts down the connection pool.
func (p *Postgres) Close() {
	p.pool.Close()
}

// ---- AuthenticationSubscription -----------------------------------------

func (p *Postgres) GetAuthSubscription(supi string) (*AuthenticationSubscription, error) {
	ctx := context.Background()
	row := p.pool.QueryRow(ctx, `
		SELECT supi, authentication_method, enc_permanent_key,
		       protection_parameter_id, sqn, sqn_scheme, amf, algorithm_id,
		       enc_opc_key, enc_topc_key
		FROM subscription_auth WHERE supi = $1`, supi)

	var s AuthenticationSubscription
	err := row.Scan(
		&s.SUPI, &s.AuthenticationMethod, &s.EncPermanentKey,
		&s.ProtectionParameterID, &s.SequenceNumber.SQN, &s.SequenceNumber.SQNScheme,
		&s.AuthenticationManagementField, &s.AlgorithmID,
		&s.EncOpcKey, &s.EncTopcKey,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("udr: auth subscription not found: %s", supi)
		}
		return nil, fmt.Errorf("udr: GetAuthSubscription: %w", err)
	}
	return &s, nil
}

func (p *Postgres) PutAuthSubscription(sub *AuthenticationSubscription) error {
	ctx := context.Background()
	_, err := p.pool.Exec(ctx, `
		INSERT INTO subscription_auth
		    (supi, authentication_method, enc_permanent_key, protection_parameter_id,
		     sqn, sqn_scheme, amf, algorithm_id, enc_opc_key, enc_topc_key)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (supi) DO UPDATE SET
		    authentication_method   = EXCLUDED.authentication_method,
		    enc_permanent_key       = EXCLUDED.enc_permanent_key,
		    protection_parameter_id = EXCLUDED.protection_parameter_id,
		    sqn                     = EXCLUDED.sqn,
		    sqn_scheme              = EXCLUDED.sqn_scheme,
		    amf                     = EXCLUDED.amf,
		    algorithm_id            = EXCLUDED.algorithm_id,
		    enc_opc_key             = EXCLUDED.enc_opc_key,
		    enc_topc_key            = EXCLUDED.enc_topc_key`,
		sub.SUPI, sub.AuthenticationMethod, sub.EncPermanentKey,
		sub.ProtectionParameterID, sub.SequenceNumber.SQN, sub.SequenceNumber.SQNScheme,
		sub.AuthenticationManagementField, sub.AlgorithmID,
		sub.EncOpcKey, sub.EncTopcKey,
	)
	if err != nil {
		return fmt.Errorf("udr: PutAuthSubscription: %w", err)
	}
	return nil
}

func (p *Postgres) UpdateSQN(supi, sqn string) error {
	ctx := context.Background()
	tag, err := p.pool.Exec(ctx,
		`UPDATE subscription_auth SET sqn = $2 WHERE supi = $1`, supi, sqn)
	if err != nil {
		return fmt.Errorf("udr: UpdateSQN: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("udr: not found: %s", supi)
	}
	return nil
}

// ---- AccessAndMobilitySubscriptionData ----------------------------------

func (p *Postgres) GetAMSubscription(supi string) (*AccessAndMobilitySubscriptionData, error) {
	ctx := context.Background()
	row := p.pool.QueryRow(ctx, `
		SELECT supi, gpsis, snssais, internal_group_ids,
		       subscribed_ue_ambr_uplink, subscribed_ue_ambr_downlink
		FROM subscription_am WHERE supi = $1`, supi)

	var s AccessAndMobilitySubscriptionData
	var gpsis, snssaisJSON, internalGroupsJSON []byte
	err := row.Scan(&s.SUPI, &gpsis, &snssaisJSON, &internalGroupsJSON,
		&s.SubscribedUEAMBRUplink, &s.SubscribedUEAMBRDownlink)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("udr: AM subscription not found: %s", supi)
		}
		return nil, fmt.Errorf("udr: GetAMSubscription: %w", err)
	}
	if err := json.Unmarshal(gpsis, &s.GPSIS); err != nil {
		return nil, fmt.Errorf("udr: unmarshal gpsis: %w", err)
	}
	if err := json.Unmarshal(snssaisJSON, &s.NSSAI.SNSSAIs); err != nil {
		return nil, fmt.Errorf("udr: unmarshal snssais: %w", err)
	}
	if err := json.Unmarshal(internalGroupsJSON, &s.InternalGroupIDs); err != nil {
		return nil, fmt.Errorf("udr: unmarshal internal_group_ids: %w", err)
	}
	return &s, nil
}

func (p *Postgres) PutAMSubscription(sub *AccessAndMobilitySubscriptionData) error {
	ctx := context.Background()
	gpsis, err := json.Marshal(sub.GPSIS)
	if err != nil {
		return err
	}
	snssais, err := json.Marshal(sub.NSSAI.SNSSAIs)
	if err != nil {
		return err
	}
	groups, err := json.Marshal(sub.InternalGroupIDs)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `
		INSERT INTO subscription_am
		    (supi, gpsis, snssais, internal_group_ids,
		     subscribed_ue_ambr_uplink, subscribed_ue_ambr_downlink)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (supi) DO UPDATE SET
		    gpsis                       = EXCLUDED.gpsis,
		    snssais                     = EXCLUDED.snssais,
		    internal_group_ids          = EXCLUDED.internal_group_ids,
		    subscribed_ue_ambr_uplink   = EXCLUDED.subscribed_ue_ambr_uplink,
		    subscribed_ue_ambr_downlink = EXCLUDED.subscribed_ue_ambr_downlink`,
		sub.SUPI, gpsis, snssais, groups,
		sub.SubscribedUEAMBRUplink, sub.SubscribedUEAMBRDownlink,
	)
	if err != nil {
		return fmt.Errorf("udr: PutAMSubscription: %w", err)
	}
	return nil
}

// ---- SMFSelectionSubscriptionData ----------------------------------------

func (p *Postgres) GetSMFSelectionSubscription(supi string) (*SMFSelectionSubscriptionData, error) {
	ctx := context.Background()
	row := p.pool.QueryRow(ctx, `
		SELECT supi, subscribed_snssai_infos FROM subscription_smf WHERE supi = $1`, supi)

	var s SMFSelectionSubscriptionData
	var infosJSON []byte
	err := row.Scan(&s.SUPI, &infosJSON)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("udr: SMF selection subscription not found: %s", supi)
		}
		return nil, fmt.Errorf("udr: GetSMFSelectionSubscription: %w", err)
	}
	if err := json.Unmarshal(infosJSON, &s.SubscribedSnssaiInfos); err != nil {
		return nil, fmt.Errorf("udr: unmarshal smf_selection: %w", err)
	}
	return &s, nil
}

func (p *Postgres) PutSMFSelectionSubscription(sub *SMFSelectionSubscriptionData) error {
	ctx := context.Background()
	infos, err := json.Marshal(sub.SubscribedSnssaiInfos)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `
		INSERT INTO subscription_smf (supi, subscribed_snssai_infos)
		VALUES ($1,$2)
		ON CONFLICT (supi) DO UPDATE SET subscribed_snssai_infos = EXCLUDED.subscribed_snssai_infos`,
		sub.SUPI, infos,
	)
	if err != nil {
		return fmt.Errorf("udr: PutSMFSelectionSubscription: %w", err)
	}
	return nil
}

// ---- SessionManagementSubscriptionData ----------------------------------

func (p *Postgres) GetSMSubscriptions(supi string) ([]SessionManagementSubscriptionData, error) {
	ctx := context.Background()
	row := p.pool.QueryRow(ctx, `SELECT sm_data FROM subscription_sm WHERE supi = $1`, supi)

	var smJSON []byte
	if err := row.Scan(&smJSON); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("udr: GetSMSubscriptions: %w", err)
	}
	var subs []SessionManagementSubscriptionData
	if err := json.Unmarshal(smJSON, &subs); err != nil {
		return nil, fmt.Errorf("udr: unmarshal sm_data: %w", err)
	}
	return subs, nil
}

func (p *Postgres) PutSMSubscriptions(supi string, subs []SessionManagementSubscriptionData) error {
	ctx := context.Background()
	smJSON, err := json.Marshal(subs)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `
		INSERT INTO subscription_sm (supi, sm_data, updated_at)
		VALUES ($1,$2,NOW())
		ON CONFLICT (supi) DO UPDATE SET sm_data = EXCLUDED.sm_data, updated_at = NOW()`,
		supi, smJSON,
	)
	if err != nil {
		return fmt.Errorf("udr: PutSMSubscriptions: %w", err)
	}
	return nil
}

// ---- PolicySubscription (URSP) ------------------------------------------

func (p *Postgres) GetPolicySubscription(supi string) (*PolicySubscription, error) {
	ctx := context.Background()
	row := p.pool.QueryRow(ctx,
		`SELECT id, supi, precedence, rules_json FROM subscription_policy WHERE supi = $1 ORDER BY precedence ASC, updated_at DESC LIMIT 1`,
		supi)

	var sub PolicySubscription
	var rulesJSON []byte
	var dbSUPI *string
	err := row.Scan(&sub.ID, &dbSUPI, &sub.Precedence, &rulesJSON)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("udr: GetPolicySubscription: %w", err)
	}
	if dbSUPI != nil {
		sub.SUPI = *dbSUPI
	}
	if err := json.Unmarshal(rulesJSON, &sub.Rules); err != nil {
		return nil, fmt.Errorf("udr: unmarshal policy rules: %w", err)
	}
	return &sub, nil
}

func (p *Postgres) PutPolicySubscription(sub *PolicySubscription) error {
	ctx := context.Background()
	rulesJSON, err := json.Marshal(sub.Rules)
	if err != nil {
		return err
	}
	var supi interface{} = sub.SUPI
	if sub.SUPI == "" {
		supi = nil
	}
	_, err = p.pool.Exec(ctx, `
		INSERT INTO subscription_policy (supi, precedence, rules_json, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (id) DO UPDATE SET
		    supi       = EXCLUDED.supi,
		    precedence = EXCLUDED.precedence,
		    rules_json = EXCLUDED.rules_json,
		    updated_at = NOW()`,
		supi, sub.Precedence, rulesJSON,
	)
	if err != nil {
		return fmt.Errorf("udr: PutPolicySubscription: %w", err)
	}
	return nil
}

func (p *Postgres) DeletePolicySubscription(supi string) error {
	ctx := context.Background()
	_, err := p.pool.Exec(ctx,
		`DELETE FROM subscription_policy WHERE supi = $1`, supi)
	if err != nil {
		return fmt.Errorf("udr: DeletePolicySubscription: %w", err)
	}
	return nil
}

func (p *Postgres) ListPolicySubscriptions() ([]*PolicySubscription, error) {
	ctx := context.Background()
	rows, err := p.pool.Query(ctx,
		`SELECT id, supi, precedence, rules_json FROM subscription_policy ORDER BY updated_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("udr: ListPolicySubscriptions: %w", err)
	}
	defer rows.Close()

	var out []*PolicySubscription
	for rows.Next() {
		var sub PolicySubscription
		var rulesJSON []byte
		var dbSUPI *string
		if err := rows.Scan(&sub.ID, &dbSUPI, &sub.Precedence, &rulesJSON); err != nil {
			return nil, fmt.Errorf("udr: ListPolicySubscriptions scan: %w", err)
		}
		if dbSUPI != nil {
			sub.SUPI = *dbSUPI
		}
		if err := json.Unmarshal(rulesJSON, &sub.Rules); err != nil {
			return nil, fmt.Errorf("udr: unmarshal policy rules: %w", err)
		}
		out = append(out, &sub)
	}
	return out, rows.Err()
}
