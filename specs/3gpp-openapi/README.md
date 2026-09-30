# 3GPP OpenAPI YAML files (Rel-17)

Reference copy of the 3GPP CT4 `5G_APIs` repository (branch `Rel-17`). The YAMLs are the
source of truth for SBI message shapes; never hand-edit them.

## Sync

```bash
make sync-openapi        # runs scripts/sync-openapi.sh
```

This clones `https://forge.3gpp.org/rep/all/5G_APIs` and copies the YAML files into this
directory. The directory ships empty apart from this README — run the sync before consulting
the specs locally.

## How they are used

SBI types are **hand-written** in `shared/types/` and in each NF's `internal/` packages,
following these schemas. There is no code generation step (`oapi-codegen` is not used) and no
automated schema checker — when adding or changing an SBI message, compare the JSON field
names, types and required/optional status against the YAML by hand.

## Most relevant files

| YAML | NF |
|---|---|
| `TS29510_Nnrf_NFManagement.yaml`, `TS29510_Nnrf_NFDiscovery.yaml`, `TS29510_Nnrf_AccessToken.yaml` | NRF |
| `TS29518_Namf_Communication.yaml`, `TS29518_Namf_Location.yaml` | AMF |
| `TS29502_Nsmf_PDUSession.yaml` | SMF |
| `TS29509_Nausf_UEAuthentication.yaml` | AUSF |
| `TS29503_Nudm_*.yaml` | UDM (UEAU, SDM, UECM) |
| `TS29504_Nudr_DR.yaml` | UDR |
| `TS29507_Npcf_AMPolicyControl.yaml`, `TS29512_Npcf_SMPolicyControl.yaml`, `TS29525_Npcf_UEPolicyControl.yaml`, `TS29514_Npcf_PolicyAuthorization.yaml` | PCF |
| `TS29531_Nnssf_NSSelection.yaml` | NSSF |
| `TS29521_Nbsf_Management.yaml` | BSF |
| `TS29572_Nlmf_Location.yaml` | LMF |
| `TS29540_Nsmsf_SMService.yaml` | SMSF |
| `TS29571_CommonData.yaml` | shared types |
