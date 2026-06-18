package procedures

import (
	"context"
	"errors"
	"fmt"

	amfctx "github.com/francurieses/claudia-5gc/nf/amf/internal/context"
)

// ErrNotConnected is returned by the UE policy delivery path when the UE is
// CM-IDLE and cannot receive a downlink NAS message directly.
// The caller should log a warning and defer the delivery until the next
// Service Request or Periodic Registration Update.
var ErrNotConnected = errors.New("UE is CM-IDLE — UE policy delivery deferred until reconnection")

// FetchUEPolicyContainer fetches updated URSP rules from the PCF (N15) and returns
// the encoded UE policy container ready to be carried in a DL NAS TRANSPORT message
// (payload container type = UE policy container).
//
// The container is a MANAGE UE POLICY COMMAND per TS 24.501 Annex D; the AMF relays
// it transparently and does not interpret its contents.
//
// Returns ErrNotConnected if the UE is CM-IDLE.
// Returns (nil, polAssoID, nil) when the PCF has no policy to deliver.
// Ref: TS 23.502 §4.2.4.3, TS 29.525 §4.2.2.2
func FetchUEPolicyContainer(
	ctx context.Context,
	ue *amfctx.UEContext,
	pcf PCFClient,
	plmn string,
) (container []byte, polAssoID string, err error) {
	ue.Lock()
	cmState := ue.CMState
	supi := ue.SUPI
	ue.Unlock()

	if cmState == amfctx.CMIdle {
		return nil, "", ErrNotConnected
	}

	polAssoID, container, err = pcf.CreateUEPolicyAssociation(ctx, supi, plmn)
	if err != nil {
		return nil, "", fmt.Errorf("uce: PCF CreateUEPolicyAssociation: %w", err)
	}
	return container, polAssoID, nil
}
