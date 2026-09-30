# shared/nas — NAS-5GS codec (TS 24.501)

Hand-written, spec-faithful NAS-5GS codec used by the AMF, SMF and the MCP NAS tools.
It does **not** wrap `github.com/free5gc/nas`; free5GC is only a reference for IE layouts.

| File | Content |
|---|---|
| `nas.go`, `ie.go` | Message header, IE primitives (TV / TLV / LV / LV-E / TLV-E), IEI constants |
| `registration.go`, `deregistration.go`, `service_request.go` | 5GMM registration, deregistration, service request |
| `auth_security.go` | Authentication, Security Mode Command/Complete |
| `transport.go` | UL/DL NAS Transport, payload containers (incl. UE policy container 0x05) |
| `configuration_update.go`, `network_name.go` | Configuration Update Command, network name IEs |
| `pdu_session.go` | 5GSM PDU session establishment / modification / release, QoS rules and flow descriptions |
| `nssaa.go`, `secondary_auth.go` | NSSAA and secondary (DN-AAA) authentication messages |

Rules:

- Encode every IE in the format TS 24.501 §9.11 mandates for it (check the IEI table in §8
  for TV vs TLV vs TLV-E before adding one) — see root `CLAUDE.md` § Protocol Encoding Rules.
- Decoders never panic on malformed input; they return an error.
- Each message type has round-trip tests; `*_wire_test.go` and `conformance_audit_test.go`
  hold byte vectors captured from UERANSIM and real UEs — add one when fixing an interop bug.

```bash
go test ./shared/nas/
```
