# EAP-AKA' Authentication (TS 33.501 §6.1.3.1 — Nausf_UEAuthentication)

## Purpose

EAP-AKA' (RFC 5448) is one of the two mandatory primary authentication methods in 5GS
(the other being 5G-AKA). The UDM/ARPF selects the method per subscriber. For EAP-AKA'
the AUSF acts as the EAP server (back-end authentication server), the SEAF/AMF is a
transparent EAP pass-through, and the UE is the EAP peer. Unlike 5G-AKA — where the AUSF
only verifies RES\* — in EAP-AKA' the AUSF runs the full EAP method: it builds the
EAP-Request/AKA'-Challenge, verifies the EAP-Response/AKA'-Challenge (RES + AT_MAC), and
on success derives K_AUSF from the EMSK.

This procedure is distinct from 5G-AKA (TS 33.501 §6.1.3.2, already implemented):
- **5G-AKA** → UDM returns RAND/AUTN/XRES\*/K_AUSF; AUSF verifies RES\*; no EAP packets.
- **EAP-AKA'** → UDM/ARPF derives CK'/IK' (TS 33.402); AUSF derives the EAP-AKA' key
  hierarchy and exchanges EAP packets with the UE through the AMF.

## Specifications

| Topic | Reference |
|---|---|
| 5G method selection & key handling | TS 33.501 §6.1.3.1, §6.1.1.3 |
| CK'/IK' derivation (KDF FC=0x20) | TS 33.402 Annex A.2 |
| EAP-AKA' protocol | RFC 5448 |
| EAP-AKA base protocol / attributes | RFC 4187 §8–§11 |
| EAP packet format | RFC 3748 §4 |
| Stage 3 (Nausf_UEAuthentication, EapSession) | TS 29.509 §5.7, §6.1.6.2 |
| KDF (PRF = HMAC-SHA-256) | TS 33.220 §B.2 |

## Key hierarchy (RFC 5448 §3.3–§3.4)

```
CK'||IK' = KDF(CK||IK, FC=0x20, P0=SN-name, P1=SQN⊕AK)      (TS 33.402 A.2)
MK       = PRF'(IK'||CK', "EAP-AKA'" || Identity)            (RFC 5448 §3.3)
           where PRF'(K,S) = T1|T2|… , Ti = HMAC-SHA-256(K, Ti-1 | S | i)
MK split : K_encr(16) | K_aut(32) | K_re(32) | MSK(64) | EMSK(64)   = 208 bytes
K_AUSF   = EMSK[0:32]   (256 most significant bits of EMSK — TS 33.501 §6.1.3.1)
K_SEAF   = KDF(K_AUSF, FC=0x6C, P0=SN-name)                  (TS 33.501 A.6)
AT_MAC   = HMAC-SHA-256-128(K_aut, EAP-packet with AT_MAC value field zeroed)
```

Golden vector (RFC 5448 Appendix C, Case 1) is encoded byte-exact in the unit tests.

## Sequence Diagram

```mermaid
sequenceDiagram
    participant UE
    participant AMF as AMF/SEAF
    participant AUSF
    participant UDM as UDM/ARPF

    UE->>AMF: Registration Request (SUCI)
    AMF->>AUSF: POST /nausf-auth/v1/ue-authentications\n{supiOrSuci, servingNetworkName}
    AUSF->>UDM: POST …/generate-auth-data\n{servingNetworkName}
    Note over UDM: AuthMethod = EAP_AKA_PRIME → derive CK'/IK' (TS 33.402)
    UDM-->>AUSF: 200 {authType:"EAP_AKA_PRIME", rand, autn, xres, ckPrime, ikPrime}
    Note over AUSF: derive MK→K_aut/EMSK; build EAP-Req/AKA'-Challenge (AT_RAND,AT_AUTN,AT_KDF,AT_KDF_INPUT,AT_MAC)
    AUSF-->>AMF: 201 Created\nLocation: …/ue-authentications/{authCtxId}\n{authType:"EAP_AKA_PRIME", 5gAuthData:{eapPayload}, _links.eap-session}
    AMF->>UE: Authentication Request (EAP-Request/AKA'-Challenge)
    UE->>UE: run AKA, derive same keys, build EAP-Response (AT_RES, AT_MAC)
    UE->>AMF: Authentication Response (EAP-Response/AKA'-Challenge)
    AMF->>AUSF: PUT …/ue-authentications/{authCtxId}/eap-session\n{eapPayload}
    Note over AUSF: verify AT_MAC (K_aut), check AT_RES == XRES
    AUSF-->>AMF: 200 {eapPayload:EAP-Success, authResult:"AUTHENTICATION_SUCCESS", kSeaf, supi}
    AMF->>UE: Authentication Result (EAP-Success)
```

## Information Elements

### Nudm_UEAuthentication_Get response (UDM → AUSF) — EAP-AKA' variant

| IE | Type | Description |
|---|---|---|
| `authType` | enum | `EAP_AKA_PRIME` |
| `rand` | hex(16) | Random challenge |
| `autn` | hex(16) | Authentication token (SQN⊕AK ‖ AMF ‖ MAC) |
| `xres` | hex(8) | Expected response (Milenage f2) |
| `ckPrime` | hex(16) | CK' (TS 33.402 A.2) |
| `ikPrime` | hex(16) | IK' (TS 33.402 A.2) |

### UeAuthenticationCtx (AUSF → AMF, 201) — TS 29.509 §6.1.6.2.3

| IE | Type | Description |
|---|---|---|
| `authType` | enum | `EAP_AKA_PRIME` |
| `5gAuthData.eapPayload` | base64 | EAP-Request/AKA'-Challenge |
| `_links.eap-session.href` | URI | PUT target for the EAP-Response |
| `servingNetworkName` | string | Echoed SN name |

### EapSession (AMF → AUSF, PUT body / AUSF → AMF, 200) — TS 29.509 §6.1.6.2.4

| IE | Type | Description |
|---|---|---|
| `eapPayload` | base64 | EAP-Response (request) / EAP-Success or Failure (response) |
| `authResult` | enum | `AUTHENTICATION_SUCCESS` / `AUTHENTICATION_FAILURE` / `AUTHENTICATION_ONGOING` |
| `kSeaf` | hex(32) | Anchor key, only on success |
| `supi` | string | Resolved SUPI, only on success |

### EAP-AKA' attributes used (RFC 4187 §10)

| Attribute | Type | Carried value |
|---|---|---|
| AT_RAND | 1 | RAND (16) |
| AT_AUTN | 2 | AUTN (16) |
| AT_RES | 3 | RES + bit length |
| AT_MAC | 11 | HMAC-SHA-256-128 over the packet |
| AT_KDF | 24 | KDF identifier (= 1) |
| AT_KDF_INPUT | 23 | Network name (access network identity) |

## Error / reject cases

| Condition | AUSF behaviour |
|---|---|
| Unknown `authCtxId` on eap-session PUT | 404 `CONTEXT_NOT_FOUND` |
| AT_MAC mismatch | 200 `authResult:"AUTHENTICATION_FAILURE"` + EAP-Failure; metric FAILURE |
| AT_RES ≠ XRES | 200 `authResult:"AUTHENTICATION_FAILURE"` + EAP-Failure; metric FAILURE |
| Malformed EAP payload | 400 `MANDATORY_IE_INCORRECT` |
| Auth context expired (> 5 min) | 404 `CONTEXT_NOT_FOUND` |

## Scope boundary

- **In scope (this task, AUSF + UDM control plane):** UDM CK'/IK' derivation gated on the
  per-subscriber `AuthMethod`; the full AUSF EAP-AKA' method (key hierarchy + packet codec +
  state machine); K_SEAF returned to the AMF on success.
- **Out of scope:** UERANSIM v3.2.8 has no EAP-AKA' peer, so the live N1 leg is not
  exercised E2E (mirrors the 5G-AKA test posture — verified by golden-vector unit tests +
  in-process godog round-trip). The AMF NAS pass-through of the EAP payload (transparent
  EAP relay in Authentication Request/Response) is a follow-up; today the AMF forwards RES\*
  for 5G-AKA only.

## Validation

- Unit: `shared/crypto/eapaka` golden vector (RFC 5448 App. C Case 1) — CK'/IK', PRF',
  K_encr/K_aut/K_re/MSK/EMSK; EAP packet encode/decode + AT_MAC round-trip.
- Unit: AUSF EAP-AKA' init + eap-session handlers (success, bad MAC, bad RES, unknown ctx).
- Functional (godog, in-process): AMF drives the EAP round-trip; AUSF returns
  AUTHENTICATION_SUCCESS with a non-empty kSeaf; a tampered AT_MAC yields FAILURE.
- Regression: 5G-AKA path unchanged (default subscriber `AuthMethod=5G_AKA`).
