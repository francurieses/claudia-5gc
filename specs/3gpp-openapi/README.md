# 3GPP OpenAPI YAML files

Reference copies of the 3GPP CT4 `5G_APIs` repository, one subdirectory per release
(`Rel-19/`, `Rel-17/`). The YAMLs are the source of truth for SBI message shapes; never
hand-edit them. They are fetched, git-ignored and never committed (only this README is tracked).

## Sync

```bash
make sync-openapi              # Rel-19 (default) -> specs/3gpp-openapi/Rel-19/
make sync-openapi REL=Rel-17   # Rel-17 -> specs/3gpp-openapi/Rel-17/ (for diffs)
```

The script maps `Rel-NN` to the upstream branch `REL-NN` (override with `OPENAPI_BRANCH`),
replaces the YAMLs of that subdirectory, and records the upstream branch and commit in
`UPSTREAM-COMMIT`. Run it before consulting the specs locally.

## How they are used

SBI types are **hand-written** in `shared/types/` and in each NF's `internal/` packages,
following these schemas. There is no code generation step (`oapi-codegen` is not used).
When adding or changing an SBI message, compare the JSON field names, types and
required/optional status against the YAML.

## Drift checker

`tools/openapi-drift` is a developer checker (not a generator). Link a Go struct to its schema
with a doc comment `// oapi: <File>.yaml#/components/schemas/<Name>` (or `// oapi: none <reason>`
to opt out), then run:

```bash
go run ./tools/openapi-drift -spec specs/3gpp-openapi/Rel-19 ./nf/... ./shared/...
go run ./tools/openapi-drift -spec specs/3gpp-openapi/Rel-17 -profile rel17 -fail-on all ./nf/... ./shared/...
go run ./tools/openapi-drift -unannotated ./nf/... ./shared/...   # structs without an annotation
go run ./tools/openapi-drift -diff specs/3gpp-openapi/Rel-17 specs/3gpp-openapi/Rel-19 -used -format md -detail direct ./nf/... ./shared/...   # Rel-17 -> Rel-19 schema delta for the APIs we use
```

Categories: `bad-annotation`, `unresolved-ref`, `missing-mandatory`, `unknown-attr`,
`type-mismatch`, `version-drift` (the `shared/sbi/apiversion` table against the YAML
`info.version` and servers URI major), `missing-yaml`. Default is report mode (exit 0);
`-fail-on <categories|all>` exits 1 on a hit; exit 2 is a usage or configuration error
(for example a missing spec directory: run `make sync-openapi REL=<Rel-NN>` first). `-format json`
is available. There is no Make target or CI job yet.

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
