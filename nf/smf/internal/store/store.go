// Package store defines the persistence contract for SMF PDU session contexts.
// Ref: 3GPP TS 23.502 §4.3.2 (PDU Session Establishment)
package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/francurieses/claudia-5gc/shared/jsoncompat"
)

// Store persists SMF PDU session contexts across restarts.
type Store interface {
	// UpsertSession creates or updates a session entry.
	UpsertSession(ctx context.Context, ref string, s *SessionRecord) error
	// DeleteSession removes the session. No-op if not found.
	DeleteSession(ctx context.Context, ref string) error
	// ListSessions returns all stored sessions (for startup reload).
	ListSessions(ctx context.Context) (map[string]*SessionRecord, error)
	// MaxCounters returns the highest SEID and UL TEID currently stored.
	// Used to seed the server's monotone counters above existing values.
	MaxCounters(ctx context.Context) (maxSEID uint64, maxTEID uint32, err error)
	// Close releases resources.
	Close()
}

// SessionRecord is the serialisable form of a PDU session.
type SessionRecord struct {
	SUPI   string `json:"supi"`
	DNN    string `json:"dnn"`
	UEIP   string `json:"ue_ip"`   // IPv4 string
	ULTEID uint32 `json:"ul_teid"` // UPF UL GTP-U TEID
	SEID   uint64 `json:"seid"`    // PFCP CP F-SEID
	SST    uint8  `json:"sst"`
	SD     string `json:"sd"`
	// PSI is the PDU Session ID (0 = unknown, rows written before migration 002).
	PSI uint8 `json:"pdu_session_id"`
	// SchemaVersion is the record schema (see SessionSchemaVersion); 0 = legacy.
	SchemaVersion int `json:"schema_version,omitempty"`
	// Extra holds keys written by a newer release so a load→save cycle keeps
	// them (TS 29.500 §6.6.2; shared/jsoncompat). Persisted in the extra column.
	Extra map[string]json.RawMessage `json:"-"`
}

// SessionSchemaVersion is the schema version this build writes.
const SessionSchemaVersion = 1

type sessionAlias SessionRecord

// UnmarshalJSON decodes the record and keeps unknown keys in Extra.
func (s *SessionRecord) UnmarshalJSON(b []byte) error {
	if err := jsoncompat.Unmarshal(b, (*sessionAlias)(s), &s.Extra); err != nil {
		return fmt.Errorf("smf store: decode SessionRecord: %w", err)
	}
	return nil
}

// MarshalJSON encodes the record with schema_version and the preserved Extra.
func (s SessionRecord) MarshalJSON() ([]byte, error) {
	s.SchemaVersion = jsoncompat.NextVersion(s.SchemaVersion, SessionSchemaVersion)
	return jsoncompat.Marshal(sessionAlias(s), s.Extra)
}

// encodeExtra serialises Extra for the extra column ("{}" when empty).
func encodeExtra(extra map[string]json.RawMessage) ([]byte, error) {
	if len(extra) == 0 {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(extra)
	if err != nil {
		return nil, fmt.Errorf("smf store: encode extra: %w", err)
	}
	return b, nil
}

// decodeExtra is the inverse of encodeExtra; empty/NULL yields nil.
func decodeExtra(b []byte) (map[string]json.RawMessage, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("smf store: decode extra: %w", err)
	}
	if len(m) == 0 {
		return nil, nil
	}
	return m, nil
}
