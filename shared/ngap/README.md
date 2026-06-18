# shared/ngap — NGAP codec (TS 38.413)

Phase 1 deliverable. Not yet implemented.

## Plan

Reuse `github.com/free5gc/ngap` + `github.com/free5gc/aper` (both Apache-2.0).
Wrap with our logging conventions in `shared/ngap/wrap.go`.

## Requirements (Phase 1 minimum)

- NG Setup Request/Response/Failure
- NG Reset / NG Reset Acknowledge
- Initial UE Message
- Downlink/Uplink NAS Transport
- Initial Context Setup Request/Response/Failure
- UE Context Release Command/Complete/Request
- Error Indication

## Phase 2 additions (PDU Session)

- PDU Session Resource Setup Request/Response/Failure
- PDU Session Resource Modify Request/Response/Failure
- PDU Session Resource Release Command/Response

## Phase 4 additions (Mobility)

- Handover Required, Handover Command, Handover Notify, Handover Cancel
- Path Switch Request, Path Switch Request Acknowledge

## Transport

NGAP runs over SCTP per TS 38.412. Use `github.com/ishidawataru/sctp`. Each
gNB-AMF association is one SCTP association with multiple streams; stream 0
is reserved for non-UE-associated signalling.
