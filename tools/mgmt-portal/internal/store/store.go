// Package store provides direct PostgreSQL access to the 5GC subscriber data.
// The portal accesses the same DB as UDR/AMF/SMF for provisioning operations.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store provides CRUD access to subscriber and session data.
type Store struct {
	pool *pgxpool.Pool
}

// New opens a connection pool to PostgreSQL.
func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("store: pgxpool.New: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("store: postgres ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close shuts down the connection pool.
func (s *Store) Close() { s.pool.Close() }

// ---- Subscriber types ---------------------------------------------------

type SNSSAI struct {
	SST uint8  `json:"sst"`
	SD  string `json:"sd"`
	DNN string `json:"dnn,omitempty"` // preferred DNN for this slice (stored in subscription_am.snssais JSONB)
}

type Subscriber struct {
	SUPI   string   `json:"supi"`
	K      string   `json:"k"`
	OPc    string   `json:"opc"`
	AMF    string   `json:"amf"`
	SQN    string   `json:"sqn"`
	Slices []SNSSAI `json:"slices"`
	AMBRUL uint64   `json:"ambr_ul"`
	AMBRDL uint64   `json:"ambr_dl"`
}

// ---- Subscribers --------------------------------------------------------

// ListSubscribers returns all provisioned subscribers.
func (s *Store) ListSubscribers(ctx context.Context) ([]Subscriber, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT a.supi, a.enc_permanent_key, a.enc_opc_key, a.amf, a.sqn,
		       COALESCE(m.snssais, '[]'::jsonb),
		       COALESCE(m.subscribed_ue_ambr_uplink, 0), COALESCE(m.subscribed_ue_ambr_downlink, 0)
		FROM subscription_auth a
		LEFT JOIN subscription_am m USING (supi)
		ORDER BY a.supi`)
	if err != nil {
		return nil, fmt.Errorf("store: ListSubscribers: %w", err)
	}
	defer rows.Close()

	var subs []Subscriber
	for rows.Next() {
		var sub Subscriber
		var snssaisJSON []byte
		if err := rows.Scan(&sub.SUPI, &sub.K, &sub.OPc, &sub.AMF, &sub.SQN,
			&snssaisJSON, &sub.AMBRUL, &sub.AMBRDL); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(snssaisJSON, &sub.Slices); err != nil {
			sub.Slices = []SNSSAI{}
		}
		subs = append(subs, sub)
	}
	return subs, rows.Err()
}

// GetSubscriber returns a single subscriber by SUPI.
func (s *Store) GetSubscriber(ctx context.Context, supi string) (*Subscriber, error) {
	var sub Subscriber
	var snssaisJSON []byte
	err := s.pool.QueryRow(ctx, `
		SELECT a.supi, a.enc_permanent_key, a.enc_opc_key, a.amf, a.sqn,
		       COALESCE(m.snssais, '[]'::jsonb),
		       COALESCE(m.subscribed_ue_ambr_uplink, 0), COALESCE(m.subscribed_ue_ambr_downlink, 0)
		FROM subscription_auth a
		LEFT JOIN subscription_am m USING (supi)
		WHERE a.supi = $1`, supi).
		Scan(&sub.SUPI, &sub.K, &sub.OPc, &sub.AMF, &sub.SQN,
			&snssaisJSON, &sub.AMBRUL, &sub.AMBRDL)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: GetSubscriber: %w", err)
	}
	if err := json.Unmarshal(snssaisJSON, &sub.Slices); err != nil {
		sub.Slices = []SNSSAI{}
	}
	return &sub, nil
}

// UpsertSubscriber creates or updates a subscriber (auth + AM data).
//
// preserveSQN must be true for updates driven by a read-modify-write client
// (the portal edit form): the SQN is network-managed state that the UDM
// increments on every authentication, so writing back the value the client
// read earlier would move it BACKWARDS. UERANSIM does not resync on a
// backwards SQN — it derives KAUSF from its own higher SQN-MS while the
// network uses the stale one, and the UE then rejects the Security Mode
// Command with an integrity failure, permanently blocking re-registration.
func (s *Store) UpsertSubscriber(ctx context.Context, sub Subscriber, preserveSQN bool) error {
	snssaisJSON, err := json.Marshal(sub.Slices)
	if err != nil {
		return err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	sqnUpdate := `sqn = EXCLUDED.sqn,`
	if preserveSQN {
		sqnUpdate = `sqn = subscription_auth.sqn,`
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO subscription_auth
		    (supi, authentication_method, enc_permanent_key, protection_parameter_id,
		     sqn, sqn_scheme, amf, algorithm_id, enc_opc_key, enc_topc_key)
		VALUES ($1,'5G_AKA',$2,'',$3,'NON_TIME_BASED',$4,'milenage',$5,'')
		ON CONFLICT (supi) DO UPDATE SET
		    enc_permanent_key = EXCLUDED.enc_permanent_key,
		    `+sqnUpdate+`
		    amf               = EXCLUDED.amf,
		    enc_opc_key       = EXCLUDED.enc_opc_key`,
		sub.SUPI, sub.K, sub.SQN, sub.AMF, sub.OPc)
	if err != nil {
		return fmt.Errorf("store: upsert auth: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO subscription_am (supi, gpsis, snssais, subscribed_ue_ambr_uplink, subscribed_ue_ambr_downlink)
		VALUES ($1,'[]'::jsonb,$2,$3,$4)
		ON CONFLICT (supi) DO UPDATE SET
		    snssais                       = EXCLUDED.snssais,
		    subscribed_ue_ambr_uplink     = EXCLUDED.subscribed_ue_ambr_uplink,
		    subscribed_ue_ambr_downlink   = EXCLUDED.subscribed_ue_ambr_downlink`,
		sub.SUPI, snssaisJSON, sub.AMBRUL, sub.AMBRDL)
	if err != nil {
		return fmt.Errorf("store: upsert am: %w", err)
	}

	return tx.Commit(ctx)
}

// DeleteSubscriber removes a subscriber and all associated data.
func (s *Store) DeleteSubscriber(ctx context.Context, supi string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Every subscription_* table must be listed: a SUPI left behind in any of
	// them is silently inherited when the same SUPI is re-created later.
	// subscription_sm and subscription_smf are distinct tables (session
	// management subscription data vs SMF selection data) — deleting only the
	// latter orphans the former.
	for _, table := range []string{
		"subscription_smf",
		"subscription_sm",
		"subscription_sm_policy",
		"subscription_policy",
		"subscription_am",
		"subscription_auth",
		"amf_ue_contexts",
		"smf_sessions",
	} {
		if _, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE supi = $1`, supi); err != nil {
			return fmt.Errorf("store: delete %s: %w", table, err)
		}
	}
	return tx.Commit(ctx)
}

// ---- PDU Sessions -------------------------------------------------------

type PDUSession struct {
	Ref       string    `json:"ref"`
	SUPI      string    `json:"supi"`
	DNN       string    `json:"dnn"`
	UEIP      string    `json:"ue_ip"`
	ULTEID    uint32    `json:"ul_teid"`
	SST       int       `json:"sst"`
	SD        string    `json:"sd"`
	CreatedAt time.Time `json:"created_at"`
}

// ListSessions returns active PDU sessions from the SMF table.
// Filters out rows with no assigned UE IP (sessions not fully established).
func (s *Store) ListSessions(ctx context.Context) ([]PDUSession, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT sm_context_ref, supi, dnn, ue_ip, ul_teid, sst, sd, created_at
		FROM smf_sessions
		WHERE ue_ip IS NOT NULL AND ue_ip != ''
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: ListSessions: %w", err)
	}
	defer rows.Close()

	var sessions []PDUSession
	for rows.Next() {
		var sess PDUSession
		if err := rows.Scan(&sess.Ref, &sess.SUPI, &sess.DNN, &sess.UEIP,
			&sess.ULTEID, &sess.SST, &sess.SD, &sess.CreatedAt); err != nil {
			return nil, err
		}
		sessions = append(sessions, sess)
	}
	return sessions, rows.Err()
}

// ---- UE Contexts --------------------------------------------------------

type UEContext struct {
	SUPI      string    `json:"supi"`
	TMSI      int64     `json:"tmsi"`
	GMMState  int       `json:"gmm_state"`
	CreatedAt time.Time `json:"created_at"`
}

// ListUEContexts returns registered UE contexts from the AMF table.
// The AMF schema uses registered_at (not created_at) and tmsi is nullable.
func (s *Store) ListUEContexts(ctx context.Context) ([]UEContext, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT supi, COALESCE(tmsi, 0), gmm_state, registered_at
		FROM amf_ue_contexts ORDER BY registered_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: ListUEContexts: %w", err)
	}
	defer rows.Close()

	var ctxs []UEContext
	for rows.Next() {
		var uc UEContext
		if err := rows.Scan(&uc.SUPI, &uc.TMSI, &uc.GMMState, &uc.CreatedAt); err != nil {
			return nil, err
		}
		ctxs = append(ctxs, uc)
	}
	return ctxs, rows.Err()
}

// ---- Policy (URSP) subscriptions -----------------------------------------

// PolicySubscription is a URSP rule set stored in subscription_policy.
// supi="" means operator default.
type PolicySubscription struct {
	ID         string          `json:"id"`
	SUPI       string          `json:"supi"`
	Precedence int             `json:"precedence"`
	Rules      json.RawMessage `json:"rules"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

// ListPolicies returns all policy subscriptions (per-subscriber + defaults).
func (s *Store) ListPolicies(ctx context.Context) ([]PolicySubscription, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, COALESCE(supi, ''), precedence, rules_json, updated_at
		FROM subscription_policy ORDER BY updated_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: ListPolicies: %w", err)
	}
	defer rows.Close()

	var policies []PolicySubscription
	for rows.Next() {
		var p PolicySubscription
		if err := rows.Scan(&p.ID, &p.SUPI, &p.Precedence, &p.Rules, &p.UpdatedAt); err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, rows.Err()
}

// GetPolicy returns a single policy subscription by ID.
func (s *Store) GetPolicy(ctx context.Context, id string) (*PolicySubscription, error) {
	var p PolicySubscription
	err := s.pool.QueryRow(ctx, `
		SELECT id, COALESCE(supi, ''), precedence, rules_json, updated_at
		FROM subscription_policy WHERE id = $1`, id).
		Scan(&p.ID, &p.SUPI, &p.Precedence, &p.Rules, &p.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: GetPolicy: %w", err)
	}
	return &p, nil
}

// UpsertPolicy creates or updates a policy subscription.
func (s *Store) UpsertPolicy(ctx context.Context, p PolicySubscription) error {
	var supi interface{} = p.SUPI
	if p.SUPI == "" {
		supi = nil
	}
	rules := p.Rules
	if len(rules) == 0 {
		rules = json.RawMessage("[]")
	}
	if p.ID == "" {
		_, err := s.pool.Exec(ctx, `
			INSERT INTO subscription_policy (supi, precedence, rules_json, updated_at)
			VALUES ($1, $2, $3, NOW())`,
			supi, p.Precedence, rules)
		return err
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO subscription_policy (id, supi, precedence, rules_json, updated_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (id) DO UPDATE SET
		    supi       = EXCLUDED.supi,
		    precedence = EXCLUDED.precedence,
		    rules_json = EXCLUDED.rules_json,
		    updated_at = NOW()`,
		p.ID, supi, p.Precedence, rules)
	return err
}

// DeletePolicy removes a policy subscription.
func (s *Store) DeletePolicy(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM subscription_policy WHERE id = $1`, id)
	return err
}

// SetSubscriberPolicy atomically replaces all per-subscriber policy rows for
// the given SUPI with a single new row. Used by handleApplyTemplate to avoid
// accumulating stale rows when the same template is applied multiple times.
func (s *Store) SetSubscriberPolicy(ctx context.Context, supi string, precedence int, rules json.RawMessage) error {
	if len(rules) == 0 {
		rules = json.RawMessage("[]")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err = tx.Exec(ctx, `DELETE FROM subscription_policy WHERE supi = $1`, supi); err != nil {
		return fmt.Errorf("store: SetSubscriberPolicy delete: %w", err)
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO subscription_policy (supi, precedence, rules_json, updated_at)
		VALUES ($1, $2, $3, NOW())`,
		supi, precedence, rules); err != nil {
		return fmt.Errorf("store: SetSubscriberPolicy insert: %w", err)
	}
	return tx.Commit(ctx)
}

// ---- Policy Templates (portal-managed) ------------------------------------

// PolicyTemplate is a named URSP template tied to a specific slice.
// Stored in portal_policy_templates (portal-only table, created by Migrate).
type PolicyTemplate struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	SliceName   string          `json:"slice_name"` // internet | gold | silver | bronze
	Precedence  int             `json:"precedence"`
	Rules       json.RawMessage `json:"rules"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// defaultTemplates seeds the 4 built-in slice templates.
var defaultTemplates = []PolicyTemplate{
	{
		Name:        "Internet — Default Slice",
		Description: "Route all traffic to the default internet slice (SST=1, SD=000001, SSC-Mode 1)",
		SliceName:   "internet",
		Precedence:  100,
		Rules:       json.RawMessage(`[{"precedence":255,"traffic_descriptor":{"match_all":true},"route_sel_descriptors":[{"precedence":1,"ssc_mode":1,"snssai":{"sst":1,"sd":"000001"},"dnn":"internet","pdu_session_type":1}]}]`),
	},
	{
		Name:        "Gold — eMBB Premium",
		Description: "Route internet DNN traffic to gold eMBB slice (SST=1, SD=000002); fall back to internet slice",
		SliceName:   "gold",
		Precedence:  50,
		Rules:       json.RawMessage(`[{"precedence":10,"traffic_descriptor":{"dnns":["internet"]},"route_sel_descriptors":[{"precedence":1,"ssc_mode":1,"snssai":{"sst":1,"sd":"000002"},"dnn":"internet","pdu_session_type":1}]},{"precedence":255,"traffic_descriptor":{"match_all":true},"route_sel_descriptors":[{"precedence":1,"ssc_mode":1,"snssai":{"sst":1,"sd":"000001"},"dnn":"internet","pdu_session_type":1}]}]`),
	},
	{
		Name:        "Silver — URLLC",
		Description: "Route all traffic to URLLC slice for low-latency applications (SST=2, SD=000001)",
		SliceName:   "silver",
		Precedence:  50,
		Rules:       json.RawMessage(`[{"precedence":10,"traffic_descriptor":{"match_all":true},"route_sel_descriptors":[{"precedence":1,"ssc_mode":1,"snssai":{"sst":2,"sd":"000001"},"dnn":"internet","pdu_session_type":1}]}]`),
	},
	{
		Name:        "Bronze — MIoT",
		Description: "Route all traffic to MIoT slice for IoT/low-throughput devices (SST=3, SD=000001)",
		SliceName:   "bronze",
		Precedence:  50,
		Rules:       json.RawMessage(`[{"precedence":10,"traffic_descriptor":{"match_all":true},"route_sel_descriptors":[{"precedence":1,"ssc_mode":1,"snssai":{"sst":3,"sd":"000001"},"dnn":"internet","pdu_session_type":1}]}]`),
	},
}

// Migrate creates portal-managed tables that are not part of the core 5GC schema.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS portal_policy_templates (
		    id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
		    name        TEXT NOT NULL,
		    description TEXT NOT NULL DEFAULT '',
		    slice_name  TEXT NOT NULL DEFAULT '',
		    precedence  INT  NOT NULL DEFAULT 100,
		    rules_json  JSONB NOT NULL DEFAULT '[]',
		    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`); err != nil {
		return err
	}
	// pws_broadcasts — the Cell Broadcast Centre (CBC) store of record for active
	// Public Warning System messages (TS 23.041). 3GPP puts the durable warning
	// state at the CBC, not the AMF (a stateless relay), so the portal — which
	// plays the CBC — persists it here. Survives AMF restart; the portal can
	// re-drive (resend) the active warnings to re-establish them at the gNBs.
	_, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS pws_broadcasts (
		    message_identifier   INT NOT NULL,
		    serial_number        INT NOT NULL,
		    data_coding_scheme   INT NOT NULL DEFAULT 15,
		    language             TEXT NOT NULL DEFAULT '',
		    warning_type         TEXT NOT NULL DEFAULT '',
		    repetition_period    INT NOT NULL DEFAULT 4096,
		    number_of_broadcasts INT NOT NULL DEFAULT 1,
		    message_text         TEXT NOT NULL DEFAULT '',
		    warning_area_tacs    INT[] NOT NULL DEFAULT '{}',
		    cancelled            BOOLEAN NOT NULL DEFAULT FALSE,
		    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		    cancelled_at         TIMESTAMPTZ,
		    PRIMARY KEY (message_identifier, serial_number)
		)`)
	return err
}

// SeedDefaultTemplates inserts the 4 built-in slice templates if the table is empty.
func (s *Store) SeedDefaultTemplates(ctx context.Context) error {
	var count int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM portal_policy_templates`).Scan(&count); err != nil {
		return fmt.Errorf("store: seed count: %w", err)
	}
	if count > 0 {
		return nil
	}
	for _, t := range defaultTemplates {
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO portal_policy_templates (name, description, slice_name, precedence, rules_json, updated_at)
			VALUES ($1, $2, $3, $4, $5, NOW())`,
			t.Name, t.Description, t.SliceName, t.Precedence, t.Rules); err != nil {
			return fmt.Errorf("store: seed template %q: %w", t.Name, err)
		}
	}
	return nil
}

// ListTemplates returns all policy templates ordered by slice name.
func (s *Store) ListTemplates(ctx context.Context) ([]PolicyTemplate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, description, slice_name, precedence, rules_json, updated_at
		FROM portal_policy_templates ORDER BY slice_name, name`)
	if err != nil {
		return nil, fmt.Errorf("store: ListTemplates: %w", err)
	}
	defer rows.Close()
	var templates []PolicyTemplate
	for rows.Next() {
		var t PolicyTemplate
		if err := rows.Scan(&t.ID, &t.Name, &t.Description, &t.SliceName, &t.Precedence, &t.Rules, &t.UpdatedAt); err != nil {
			return nil, err
		}
		templates = append(templates, t)
	}
	return templates, rows.Err()
}

// GetTemplate returns a single template by ID.
func (s *Store) GetTemplate(ctx context.Context, id string) (*PolicyTemplate, error) {
	var t PolicyTemplate
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, description, slice_name, precedence, rules_json, updated_at
		FROM portal_policy_templates WHERE id = $1`, id).
		Scan(&t.ID, &t.Name, &t.Description, &t.SliceName, &t.Precedence, &t.Rules, &t.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: GetTemplate: %w", err)
	}
	return &t, nil
}

// UpsertTemplate creates or updates a policy template.
func (s *Store) UpsertTemplate(ctx context.Context, t PolicyTemplate) error {
	rules := t.Rules
	if len(rules) == 0 {
		rules = json.RawMessage("[]")
	}
	if t.ID == "" {
		_, err := s.pool.Exec(ctx, `
			INSERT INTO portal_policy_templates (name, description, slice_name, precedence, rules_json, updated_at)
			VALUES ($1, $2, $3, $4, $5, NOW())`,
			t.Name, t.Description, t.SliceName, t.Precedence, rules)
		return err
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO portal_policy_templates (id, name, description, slice_name, precedence, rules_json, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (id) DO UPDATE SET
		    name        = EXCLUDED.name,
		    description = EXCLUDED.description,
		    slice_name  = EXCLUDED.slice_name,
		    precedence  = EXCLUDED.precedence,
		    rules_json  = EXCLUDED.rules_json,
		    updated_at  = NOW()`,
		t.ID, t.Name, t.Description, t.SliceName, t.Precedence, rules)
	return err
}

// DeleteTemplate removes a template by ID.
func (s *Store) DeleteTemplate(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM portal_policy_templates WHERE id = $1`, id)
	return err
}

// ---- Public Warning System (CBC store of record — TS 23.041) --------------

// PWSBroadcast is one Public Warning System warning message the portal (acting
// as the Cell Broadcast Centre) has broadcast, persisted so it survives an AMF
// restart and can be re-driven to the gNBs. Mirrors the fields the AMF mgmt
// API POST /amf/v1/pws/broadcast accepts, so a stored record fully reconstructs
// the request. Ref: TS 23.041, TS 38.413 §8.9.
type PWSBroadcast struct {
	MessageIdentifier  int        `json:"message_identifier"`
	SerialNumber       int        `json:"serial_number"`
	DataCodingScheme   int        `json:"data_coding_scheme"`
	Language           string     `json:"language"`
	WarningType        string     `json:"warning_type"`
	RepetitionPeriod   int        `json:"repetition_period"`
	NumberOfBroadcasts int        `json:"number_of_broadcasts"`
	MessageText        string     `json:"message_text"`
	WarningAreaTACs    []int32    `json:"warning_area_tacs"`
	Cancelled          bool       `json:"cancelled"`
	CreatedAt          time.Time  `json:"created_at"`
	CancelledAt        *time.Time `json:"cancelled_at,omitempty"`
}

// UpsertPWSBroadcast records a broadcast (or replaces an existing one keyed by
// message identifier + serial number — the "Write-Replace" semantics of
// TS 23.041). A (re-)broadcast resets the cancelled flag and refreshes
// created_at, since it re-establishes the warning at the RAN.
func (s *Store) UpsertPWSBroadcast(ctx context.Context, b PWSBroadcast) error {
	tacs := b.WarningAreaTACs
	if tacs == nil {
		tacs = []int32{}
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO pws_broadcasts (
		    message_identifier, serial_number, data_coding_scheme, language,
		    warning_type, repetition_period, number_of_broadcasts, message_text,
		    warning_area_tacs, cancelled, created_at, cancelled_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,FALSE,NOW(),NULL)
		ON CONFLICT (message_identifier, serial_number) DO UPDATE SET
		    data_coding_scheme   = EXCLUDED.data_coding_scheme,
		    language             = EXCLUDED.language,
		    warning_type         = EXCLUDED.warning_type,
		    repetition_period    = EXCLUDED.repetition_period,
		    number_of_broadcasts = EXCLUDED.number_of_broadcasts,
		    message_text         = EXCLUDED.message_text,
		    warning_area_tacs    = EXCLUDED.warning_area_tacs,
		    cancelled            = FALSE,
		    created_at           = NOW(),
		    cancelled_at         = NULL`,
		b.MessageIdentifier, b.SerialNumber, b.DataCodingScheme, b.Language,
		b.WarningType, b.RepetitionPeriod, b.NumberOfBroadcasts, b.MessageText, tacs)
	if err != nil {
		return fmt.Errorf("store: UpsertPWSBroadcast: %w", err)
	}
	return nil
}

// MarkPWSCancelled flags a stored broadcast cancelled. No error if the row does
// not exist (the cancel is still relayed to the AMF regardless).
func (s *Store) MarkPWSCancelled(ctx context.Context, messageIdentifier, serialNumber int) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE pws_broadcasts SET cancelled = TRUE, cancelled_at = NOW()
		WHERE message_identifier = $1 AND serial_number = $2`,
		messageIdentifier, serialNumber)
	if err != nil {
		return fmt.Errorf("store: MarkPWSCancelled: %w", err)
	}
	return nil
}

// ListPWSBroadcasts returns every stored warning, newest first.
func (s *Store) ListPWSBroadcasts(ctx context.Context) ([]PWSBroadcast, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT message_identifier, serial_number, data_coding_scheme, language,
		       warning_type, repetition_period, number_of_broadcasts, message_text,
		       warning_area_tacs, cancelled, created_at, cancelled_at
		FROM pws_broadcasts ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: ListPWSBroadcasts: %w", err)
	}
	defer rows.Close()
	var out []PWSBroadcast
	for rows.Next() {
		var b PWSBroadcast
		if err := rows.Scan(&b.MessageIdentifier, &b.SerialNumber, &b.DataCodingScheme,
			&b.Language, &b.WarningType, &b.RepetitionPeriod, &b.NumberOfBroadcasts,
			&b.MessageText, &b.WarningAreaTACs, &b.Cancelled, &b.CreatedAt, &b.CancelledAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// GetPWSBroadcast returns one stored warning, or nil if not found.
func (s *Store) GetPWSBroadcast(ctx context.Context, messageIdentifier, serialNumber int) (*PWSBroadcast, error) {
	var b PWSBroadcast
	err := s.pool.QueryRow(ctx, `
		SELECT message_identifier, serial_number, data_coding_scheme, language,
		       warning_type, repetition_period, number_of_broadcasts, message_text,
		       warning_area_tacs, cancelled, created_at, cancelled_at
		FROM pws_broadcasts WHERE message_identifier = $1 AND serial_number = $2`,
		messageIdentifier, serialNumber).Scan(
		&b.MessageIdentifier, &b.SerialNumber, &b.DataCodingScheme, &b.Language,
		&b.WarningType, &b.RepetitionPeriod, &b.NumberOfBroadcasts, &b.MessageText,
		&b.WarningAreaTACs, &b.Cancelled, &b.CreatedAt, &b.CancelledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: GetPWSBroadcast: %w", err)
	}
	return &b, nil
}
