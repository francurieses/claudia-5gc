# CLAUDE.md — UDM (Unified Data Management)

> Read the root `CLAUDE.md` first for global conventions.

## 1. Function

UDM manages subscription data and is the entry point for HPLMN authentication. Contains the SIDF (Subscription Identifier De-concealing Function) to resolve SUCI→SUPI.

**Primary specifications:**
- **TS 29.503** — Nudm services (Stage 3)
- TS 33.501 §6.12 — SUCI deconcealment (SIDF)
- TS 29.505 — UDM subscription data

## 2. Reference Points

| Interface | Peer | Protocol | Spec |
|---|---|---|---|
| N8 | AMF | Nudm_SDM, Nudm_UECM | TS 29.503 |
| N13 | AUSF | Nudm_UEAuthentication | TS 29.503 |
| N35 | UDR | Nudr_DR | TS 29.504 |

## 3. Provided SBI Services

| Service | Operation | Route | Spec |
|---|---|---|---|
| Nudm_UEAuthentication | GenerateAuthData | `POST /nudm-ueau/v1/{supi}/security-information/generate-auth-data` | §5.2.2.2 |
| Nudm_SDM | Get AM data | `GET /nudm-sdm/v2/{supi}/am-data` | §5.2.2.2 |
| Nudm_SDM | Get SM data | `GET /nudm-sdm/v2/{supi}/sm-data` (filters: `dnn`, `single-nssai`) | §5.2.2.2 / §6.1.6.2.7 |
| Nudm_UECM | AMF Registration | `PUT /nudm-uecm/v1/{supi}/registrations/amf-3gpp-access` | §5.3.2.2 |

## 4. Implementation Status

| Function | Status |
|---|---|
| SUCI deconcealment (null scheme) | ✅ Functional |
| SUCI Profile A (X25519 ECIES) | ✅ Functional — configure `hn_private_key_x25519` in dev.yaml |
| SUCI Profile B (secp256r1 ECIES) | ⏳ TODO |
| GenerateAuthData (5G-AKA via Milenage) | ✅ Functional |
| SQN increment and update in UDR | ✅ Functional |
| Get AM subscription data | ✅ Functional |
| Get SM subscription data (defaultQos per slice/DNN) | ✅ Functional |
| AMF UECM registration | ✅ Functional |

## 5. SUCI Deconcealment (SIDF)

`handleGenerateAuthData` receives the `supi` path parameter which can be SUPI or SUCI:

```
if strings.HasPrefix(supi, "suci-"):
    ParseSUCIString → SUCI struct
    switch ProtectionScheme:
        case ProfileNull(0): DeconceaNull → SUPI
        case ProfileA/B:     501 Not Implemented (requires HN private key)
```

Logic is in `shared/crypto/suci/`. MSIN in null-scheme comes in BCD low-nibble-first (3GPP OTA format): `0000000001` → bytes `[00 00 00 00 10]`.

## 6. 5G HE AV Generation

Uses `shared/aka.GenerateFull` which calls Milenage + KDF chain:
`KAUSF = KDF(CK||IK, "5G_AKA", SN-name, SQN XOR AK)`
KAUSF is included in the JSON response to AUSF.

## 7. Commands

```bash
make -C nf/udm build
make -C nf/udm test
make -C nf/udm docker
```
