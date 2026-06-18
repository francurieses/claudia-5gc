# shared/pfcp — PFCP codec (TS 29.244)

Phase 2 deliverable. Not yet implemented.

## Plan

Either reuse `github.com/wmnsk/go-pfcp` (MIT) or build a thin wrapper. The
go-pfcp library is well-maintained and covers Rel-17 IEs.

## Requirements

- Heartbeat Request/Response (§7.4.2)
- Association Setup/Update/Release Request/Response (§7.4.4)
- Session Establishment/Modification/Deletion Request/Response (§7.5.2–7.5.4)
- Session Report Request/Response (§7.5.8)
- Node Report Request/Response

## IE coverage (minimum)

PDR (Packet Detection Rule), FAR (Forwarding Action), QER (QoS Enforcement),
URR (Usage Reporting), BAR (Buffering Action). Plus all referenced IEs:
F-SEID, F-TEID, PDI, Apply Action, etc.

## Transport

UDP port 8805 per TS 29.244 §6.

## Reference points

- N4 (SMF ↔ UPF)
