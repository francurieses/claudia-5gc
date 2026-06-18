// Package store defines the persistence contract for SMF PDU session contexts.
// Ref: 3GPP TS 23.502 §4.3.2 (PDU Session Establishment)
package store

import "context"

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
}
