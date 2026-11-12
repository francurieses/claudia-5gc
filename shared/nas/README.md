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
| `ietable.go` | Per-message IEI→format tables (TV1/T/TV/TLV/TLV-E, `Introduced` release verified against TS 24.501 V15.7/V16.15/V17.18/V18.14/V19.8) for Registration Request/Accept, PDU Session Establishment Request, Service Request/Accept, Configuration Update Command, UL/DL NAS Transport, Authentication Request/Response and Security Mode Command/Complete (TS 24.501 V19.8.0 clause 8) and the generic `skipIE` (TS 24.007 §11.2.4) |
| `cause.go` | Complete 5GMM/5GSM cause tables (TS 24.501 V19.8.0 Table 9.11.3.2.1 / 9.11.4.2.1) with `Introduced` release tags, `LookupCause5GMM`/`LookupCause5GSM`, `Cause5GMM.String`, `Cause5GSMName`, unknown-value mapping (5GMM → #111; 5GSM UE → #31, network → #111) |
| `iei_rel18.go` | Rel-18/19 IEI constants (TS 24.501 §9.11); `service_request.go` `InterpretServiceType` follows Table 9.11.3.50.1 (`ServiceTypeHighPriorityAccess` = 0x05) |
| `capability_ie.go` | 5GMM capability (TS 24.501 V19.8.0 §9.11.3.1, 82 bits incl. Rel-18/19 octets) and 5GSM capability (§9.11.4.1) `Decode*`/`Encode*` into bit structs with `Raw` preservation (spare/extra octets) and `Introduced` release tags; `PeerUE` adapter to `capability.PeerUE` (map featureID→predicate). Exposed by `RegistrationRequest` and PDU Session Establishment Request (IEI 0x28) |
| `nssaa.go`, `secondary_auth.go` | NSSAA and secondary (DN-AAA) authentication messages |

Rules:

- Encode every IE in the format TS 24.501 §9.11 mandates for it (check the IEI table in §8
  for TV vs TLV vs TLV-E before adding one) — see root `CLAUDE.md` § Protocol Encoding Rules.
- Decoders never panic on malformed input; they return an error.
- Unknown optional IEs are skipped (TS 24.501 §7.6.1); a syntactically incorrect or truncated optional IE is treated as absent and stops optional-IE parsing (§7.7.1). Not yet table-driven: Service Request, Configuration Update, NAS transport, Authentication, SMC.
- Each message type has round-trip tests; `*_wire_test.go` and `conformance_audit_test.go`
  hold byte vectors captured from UERANSIM and real UEs — add one when fixing an interop bug.

```bash
go test ./shared/nas/
```

### Fuzzing

`fuzz_test.go` holds one native Go fuzz target per exported `Decode*` (`FuzzDecode<Name>`, plus
`FuzzParseIPCPFromEPCO`), round-trip properties (NSSAI, UE security capability, network name,
rejected NSSAI) and header-consistency checks for `nas.Decode`. `TestFuzzTargetsCoverDecoders`
fails when a new exported `Decode*` has no fuzz target.

```bash
go test ./shared/nas/ -run '^$' -fuzz '^FuzzDecodeRegistrationRequest$' -fuzztime 60s
```

### 5GS network feature support IE (TS 24.501 §9.11.3.5)

`network_feature_support.go`: typed `NetworkFeatureSupport` (octets 3-6), `Encode(maxOctets)` (trailing zero octets truncated, min 2 octets = legacy form, max 6), tolerant `DecodeNetworkFeatureSupport`, `LimitToUECapability` (clears bits the UE did not indicate in its 5GMM capability, §5.5.1.2.4/§5.5.1.3.4; MLCSUP implies LCS-UPP, PR needs RPR and/or NCR) and `DropAfterRel17`. Fuzz target `FuzzDecodeNetworkFeatureSupport`. The AMF uses it behind capability feature `NAS-NFS-EXT` (see `nf/amf/CLAUDE.md`).
