// Package store defines the persistence contracts for AMF UE contexts.
// Ref: 3GPP TS 23.501 §5.3 (UE context); TS 23.502 §4.2.2.2.2 (registration)
package store

import (
	"context"
	"time"
)

// gmmStateRegistered mirrors context.GMMRegistered (iota = 1).
// Used in SQL queries; must stay in sync with context.GMM5State.
const gmmStateRegistered = 1

// Store persists AMF UE registration contexts across restarts.
type Store interface {
	// UpsertUE creates or updates a UE context keyed by SUPI.
	UpsertUE(ctx context.Context, rec *UERecord) error
	// GetUEBySUPI returns nil, nil when not found.
	GetUEBySUPI(ctx context.Context, supi string) (*UERecord, error)
	// GetUEByTMSI returns nil, nil when not found.
	GetUEByTMSI(ctx context.Context, tmsi uint32) (*UERecord, error)
	// DeleteUE removes the UE context; no-op if not found.
	DeleteUE(ctx context.Context, supi string) error
	// ListRegisteredUEs returns all GMMRegistered UEs.
	ListRegisteredUEs(ctx context.Context) ([]*UERecord, error)
	// ListAllUEContexts returns every persisted UE context regardless of 5GMM
	// state. Used at startup to release SM contexts before purging.
	ListAllUEContexts(ctx context.Context) ([]*UERecord, error)
	// MaxTMSI returns the highest TMSI currently stored, or 0 if none.
	MaxTMSI(ctx context.Context) (uint32, error)
	// PurgeAllUEContexts deletes all rows; returns the number of rows deleted.
	PurgeAllUEContexts(ctx context.Context) (int64, error)
	// Close releases resources.
	Close()
}

// Cache provides atomic counters that survive AMF restarts.
type Cache interface {
	// SeedTMSIIfLower ensures the TMSI counter is at least minVal.
	// Call at startup with the result of Store.MaxTMSI to avoid reuse.
	SeedTMSIIfLower(ctx context.Context, minVal uint32) error
	// NextTMSI returns the next unique 5G-TMSI value.
	NextTMSI(ctx context.Context) (uint32, error)
	// Close releases resources.
	Close() error
}

// ---- Serialisable record types ------------------------------------------

// UERecord is the serialisable form of a UEContext stored in PostgreSQL.
type UERecord struct {
	SUPI             string             `json:"supi"`
	GUTI             *GUTIRecord        `json:"guti,omitempty"`
	GMMState         int                `json:"gmm_state"`
	CMState          int                `json:"cm_state"`
	SecurityCtx      SecurityRecord     `json:"security_ctx"`
	RawUESecCap      []byte             `json:"raw_ue_sec_cap,omitempty"`
	AllowedNSSAI     []SNSSAIRecord     `json:"allowed_nssai"`
	RequestedNSSAI   []SNSSAIRecord     `json:"requested_nssai,omitempty"`
	SubscribedAMBRUL uint64             `json:"subscribed_ambr_ul"`
	SubscribedAMBRDL uint64             `json:"subscribed_ambr_dl"`
	PDUSessions      []PDUSessionRecord `json:"pdu_sessions"`
	RegistrationTime time.Time          `json:"registration_time"`
	LastActivity     time.Time          `json:"last_activity"`
}

// GUTIRecord is the serialisable 5G-GUTI.
type GUTIRecord struct {
	MCC         string `json:"mcc"`
	MNC         string `json:"mnc"`
	AMFRegionID byte   `json:"amf_region_id"`
	AMFSetID    uint16 `json:"amf_set_id"`
	AMFID       byte   `json:"amf_id"`
	TMSI        uint32 `json:"tmsi"`
}

// SecurityRecord is the serialisable NAS security context (TS 33.501 §6.7).
type SecurityRecord struct {
	NGKSI          byte   `json:"ngksi"`
	IntegrityAlgID byte   `json:"integrity_alg_id"`
	CipheringAlgID byte   `json:"ciphering_alg_id"`
	KAMF           []byte `json:"kamf,omitempty"`
	KNASint        []byte `json:"knas_int,omitempty"`
	KNASenc        []byte `json:"knas_enc,omitempty"`
	UplinkCount    uint32 `json:"uplink_count"`
	DownlinkCount  uint32 `json:"downlink_count"`
	Active         bool   `json:"active"`
}

// SNSSAIRecord is a serialisable S-NSSAI.
type SNSSAIRecord struct {
	SST uint8  `json:"sst"`
	SD  string `json:"sd,omitempty"`
	DNN string `json:"dnn,omitempty"` // portal-assigned preferred DNN; empty = no preference
}

// PDUSessionRecord is a serialisable PDU session entry.
type PDUSessionRecord struct {
	PDUSessionID   uint8        `json:"pdu_session_id"`
	SMFInstanceID  string       `json:"smf_instance_id"`
	SMFAddress     string       `json:"smf_address"`
	SNSSAI         SNSSAIRecord `json:"snssai"`
	DNN            string       `json:"dnn"`
	PDUSessionType string       `json:"pdu_session_type"`
	QFIs           []uint8      `json:"qfis,omitempty"`
	N2SmTransfer   []byte       `json:"n2_sm_transfer,omitempty"`
}
