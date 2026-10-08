// Package mgmt holds read-only handlers of the AMF management API (plain HTTP,
// port 9002) that need to be testable apart from cmd/amf.
package mgmt

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/francurieses/claudia-5gc/nf/amf/internal/ngap"
)

// GNBLister is the view of the NGAP server needed by the gNB list handler.
type GNBLister interface {
	GNBSnapshots() []ngap.GNBSnapshot
	N2ListenAddr() string
}

// AMFInfo identifies the AMF in the gNB list envelope.
type AMFInfo struct {
	Name     string
	MCC, MNC string
	RegionID uint
	SetID    uint
	AMFID    uint
}

type amfEnvelope struct {
	Name     string        `json:"name"`
	PLMN     ngap.PLMNJSON `json:"plmn"`
	RegionID uint          `json:"region_id"`
	SetID    uint          `json:"set_id"`
	AMFID    uint          `json:"amf_id"`
	N2Addr   string        `json:"n2_addr"`
}

type gnbListResponse struct {
	AMF         amfEnvelope        `json:"amf"`
	GeneratedAt time.Time          `json:"generated_at"`
	GNBs        []ngap.GNBSnapshot `json:"gnbs"`
}

// GNBListHandler serves GET /amf/v1/ran/gnbs: the gNBs connected over N2 plus
// recently disconnected ones. The portal polls it every few seconds, so each
// call is logged at DEBUG only.
// Ref: TS 38.413 §8.7.1 (NG Setup), TS 38.412 §7.
func GNBListHandler(l GNBLister, amf AMFInfo, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		gnbs := l.GNBSnapshots()
		if gnbs == nil {
			gnbs = []ngap.GNBSnapshot{}
		}
		logger.Debug("RAN status query",
			"nf", "AMF",
			"procedure", "RANStatusQuery",
			"interface", "Mgmt",
			"direction", "IN",
			"gnb_count", len(gnbs),
		)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(gnbListResponse{
			AMF: amfEnvelope{
				Name:     amf.Name,
				PLMN:     ngap.PLMNJSON{MCC: amf.MCC, MNC: amf.MNC},
				RegionID: amf.RegionID,
				SetID:    amf.SetID,
				AMFID:    amf.AMFID,
				N2Addr:   l.N2ListenAddr(),
			},
			GeneratedAt: time.Now().UTC(),
			GNBs:        gnbs,
		})
	}
}
