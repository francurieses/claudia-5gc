# CLAUDE.md — AUSF (Authentication Server Function)

> Read the root `CLAUDE.md` first for global conventions.

## 1. Function

AUSF performs UE authentication on behalf of the HPLMN. Coordinates with UDM to obtain the authentication vector (5G HE AV) and verifies the UE's RES*.

**Primary specifications:**
- TS 23.502 §4.2.2.2.2 — 5G-AKA flow
- **TS 29.509** — Nausf_UEAuthentication (Stage 3)
- TS 33.501 §6.1 — 5G-AKA authentication procedure

## 2. Reference Points

| Interface | Peer | Protocol | Spec |
|---|---|---|---|
| N12 | AMF | Nausf SBI | TS 29.509 |
| N13 | UDM | Nudm SBI | TS 29.503 |

## 3. Provided SBI Services (TS 29.509)

| Operation | Route | Spec |
|---|---|---|
| UEAuthenticationPost | `POST /nausf-auth/v1/ue-authentications` | §5.7 |
| 5gAkaConfirmation | `PUT /nausf-auth/v1/ue-authentications/{authCtxId}/5g-aka-confirmation` | §5.8 |
| EapAuthMethod (EAP-AKA') | `PUT /nausf-auth/v1/ue-authentications/{authCtxId}/eap-session` | §5.7 |
| DeleteAuthentication | `DELETE /nausf-auth/v1/ue-authentications/{authCtxId}` | §5.9 |
| NSSAA EAP relay (simulated AAA-S) | `POST /nausf-nssaa/v1/{supi}/authenticate` | TS 23.502 §4.2.9 |

## 4. Implementation Status

| Procedure | Status |
|---|---|
| 5G-AKA initiation (→ UDM) | ✅ Functional |
| RES* verification + KAUSF derivation | ✅ Functional |
| EAP-AKA' | ✅ Functional — `PUT …/eap-session`; key hierarchy + codec in `shared/crypto/eapaka` (RFC 5448) |
| NSSAA EAP relay | 🟡 `POST /nausf-nssaa/v1/{supi}/authenticate` — relays UE EAP-Response to a simulated AAA-S (single round: Identity→Success/Failure; rejects identity containing "reject"). Generic EAP framing in `shared/crypto/eap`. No standalone NSSAAF / real AAA-S |

## 5. 5G-AKA Flow

1. AMF POSTs `ue-authentications` with SUCI/SUPI.
2. AUSF calls UDM `POST /nudm-ueau/v1/{suci}/security-information/generate-auth-data`.
   UDM resolves SUCI→SUPI, generates HE AV via Milenage, returns RAND/AUTN/XRES*/HXRES*/KAUSF.
3. AUSF stores context (authCtxId UUID), returns RAND/AUTN to AMF.
4. AMF sends Authentication Request to UE; UE responds with RES*.
5. AMF PUTs `5g-aka-confirmation` with RES*. AUSF verifies HRES*=SHA256(RAND||RES*) against HXRES*.
6. On success: AUSF returns KAUSF and SUPI to AMF.

**Auth contexts**: stored in Redis (`ausf:auth:{authCtxId}`, TTL = 5 min) when `REDIS_URL` is configured; in memory otherwise. Implemented in `shared/aka/redis_store.go`. Redis TTL replaces the `time.Since(ctx.CreatedAt) > 5*time.Minute` check in `VerifyRES` when Redis is active.

## 6. Implementation Notes

- The `supi` field in UDM's response (`generate-auth-data`) contains the SUPI resolved from SUCI — AUSF propagates it to AMF in the confirmation response.
- KAUSF is generated in UDM (not AUSF) via `shared/aka.GenerateFull`. AUSF receives and forwards it.

## 7. Commands

```bash
make -C nf/ausf build
make -C nf/ausf test
make -C nf/ausf docker
```
