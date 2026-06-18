# 3GPP OpenAPI YAML files (Rel-17)

These YAML files are the **authoritative source of truth** for SBI types.
Hand-editing them is forbidden — they're a verbatim copy of the 3GPP CT4
maintained `5G_APIs` repository, REL-17 branch.

## Sync

```bash
make sync-specs
```

This runs `tools/sync-3gpp-openapi.sh`, which clones the latest REL-17
snapshot from `https://forge.3gpp.org/rep/all/5G_APIs` and copies the YAML
files here. The commit SHA and timestamp are recorded in `.SNAPSHOT_COMMIT`
and `.SNAPSHOT_DATE`.

## Code generation

NF code generates Go types from these YAMLs using `oapi-codegen`. Each NF's
Makefile (or `make build` target) regenerates as part of the build.

Example (in an NF directory):

```bash
oapi-codegen -generate types,client \
  -package nrfgen \
  ../../specs/3gpp-openapi/TS29510_Nnrf_NFManagement.yaml \
  > internal/sbi/nrfgen/types.go
```

## Critical YAML files for the MVP

- `TS29510_Nnrf_NFManagement.yaml` — NRF
- `TS29510_Nnrf_NFDiscovery.yaml`
- `TS29510_Nnrf_AccessToken.yaml`
- `TS29518_Namf_Communication.yaml` — AMF
- `TS29518_Namf_EventExposure.yaml`
- `TS29502_Nsmf_PDUSession.yaml` — SMF
- `TS29509_Nausf_UEAuthentication.yaml` — AUSF
- `TS29503_Nudm_*.yaml` — UDM (UEAuthentication, SDM, UECM, …)
- `TS29504_Nudr_DR.yaml` — UDR
- `TS29507_Npcf_AMPolicyControl.yaml`, `TS29512_Npcf_SMPolicyControl.yaml` — PCF
- `TS29531_Nnssf_NSSelection.yaml` — NSSF
- `TS29571_CommonData.yaml` — shared types
