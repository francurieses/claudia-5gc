# Network Exposure Function — Nnef_AFsessionWithQoS (TS 23.501 §6.2.5 / TS 29.522 §4.4.13)

## Purpose

The **Network Exposure Function (NEF)** is the 5GC's secure gateway between the trusted
core and external **Application Functions (AFs)**: it exposes selected core capabilities
northbound over the **Nnef** API surface (TS 29.522) while shielding internal NFs and
hiding network topology. Today the core has **no northbound exposure** — an AF cannot ask
the network for anything.

This task adds the **NEF NF** and its baseline northbound API, **AsSessionWithQoS**
(`Nnef_AFsessionWithQoS`, TS 29.522 §4.4.13): the standard "AF requests a guaranteed QoS
for an application flow toward a UE" flow. An AF knows only the **UE's IP address** and an
application/flow descriptor; it does not know which PCF serves that UE. The NEF resolves
that gap by **discovering the serving PCF via the BSF** (`Nbsf_Management_Discovery`,
already built in BSF-001), then **maps the request onto a PCF policy-authorization
operation** (`Npcf_PolicyAuthorization_Create`, TS 29.514) so the PCF installs the
authorized QoS on the UE's PDU session. The AF interface is **OAuth2-protected** on top of
the always-on SBA mTLS; the AF is identified by the `scsAsId` path segment plus an `afId`.

> **Why NEF-001 depends on BSF-001.** The AF supplies a UE IP, not a PCF. The NEF cannot
> address the serving PCF without `Nbsf_Management_Discovery`
> (`GET /nbsf-management/v1/pcfBindings?ipv4Addr=…` → `PcfBinding`, TS 29.521 §6.2.6).
> BSF-001 built and tested that Discovery operation precisely so NEF-001 consumes it
> unchanged.

> **Scope boundary.** This increment delivers the baseline only:
> (1) the **NEF NF** (SBA server, NRF register + heartbeat, `/healthz` + `/metrics`);
> (2) the **AsSessionWithQoS** northbound resource — **Create / Get / Delete**;
> (3) **BSF Discovery** consumption to find the serving PCF; (4) a **thin new PCF
> endpoint** `Npcf_PolicyAuthorization_Create` (`POST /npcf-policyauthorization/v1/app-sessions`)
> that the NEF Create maps onto. **Out of scope** (deferred): event notifications back to
> the AF (QoS Notification Control / usage-monitoring callbacks), `Nnef_EventExposure`, PFD
> management, the full TS 29.514 app-session lifecycle (Update / event-subscribe / Patch),
> and **docker-compose service wiring** (hard-stop surface — deferred like BSF-004; this doc
> states the recommended ports but does not wire compose/Prometheus). The NEF is
> **SBA-only**: no N1/N2/N4 path is touched.

## Specifications

| Topic | Reference |
|---|---|
| NEF functional description | TS 23.501 §6.2.5 |
| Network exposure architecture / procedures | TS 23.502 §4.15 |
| AF-requested QoS (Stage 2 flow) | TS 23.502 §4.15.6.6 |
| Nnef_AFsessionWithQoS (Stage 3) | TS 29.522 §4.4.13 |
| Data type `AsSessionWithQoSSubscription` | TS 29.522 §5.14.2.1.2 |
| Nbsf_Management_Discovery (PCF lookup) | TS 29.521 §5.2.2.4, `PcfBinding` §6.2.6 |
| Npcf_PolicyAuthorization (PCF leg) | TS 29.514 §5.2.2.2 (Create), data §5.6.2.3 |
| OAuth2 / token protection of northbound API | TS 29.522 §6, TS 29.510 §6.3 (NRF token model) |
| SBA framework / ProblemDetails | TS 29.500 §5.2.7, TS 29.571 §5.2.7 |
| NRF registration (`NFType` NEF) | TS 29.510 §6.1.6.2.2 |

## Sequence Diagram

The AF creates an AsSessionWithQoS subscription. The NEF acquires/verifies an OAuth2 token,
discovers the serving PCF by UE IP via the BSF, then creates an app-session on that PCF.
`201 Created` propagates back up the chain.

```mermaid
sequenceDiagram
    participant AF
    participant NRF
    participant NEF
    participant BSF
    participant PCF

    Note over NEF,NRF: NEF startup — service registration
    NEF->>NRF: PUT /nnrf-nfm/v1/nf-instances/{nefId}\nNFProfile{nfType:NEF, nnef-afsessionwithqos} (TS 29.510 §6.1.6.2.2)
    NRF-->>NEF: 201 Created NFProfile

    Note over AF,NEF: OAuth2 token (northbound) — AF presents a bearer token
    AF->>NRF: POST /oauth2/token (client_credentials, scope=nnef-afsessionwithqos) (TS 29.510 §6.3.5.2.2)
    NRF-->>AF: 200 access_token (HS256 JWT)

    Note over AF,NEF: AsSessionWithQoS — Create
    AF->>NEF: POST /3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions\nAuthorization: Bearer <token>\nAsSessionWithQoSSubscription{ueIpv4Addr, flowInfo, qosReference, notificationDestination} (TS 29.522 §4.4.13.2.5)
    NEF->>NEF: verify bearer token + scope; resolve AF id (scsAsId/afId) (TS 29.522 §6)
    alt token invalid / missing scope
        NEF-->>AF: 401/403 ProblemDetails
    end

    Note over NEF,BSF: discover serving PCF by UE IP (consumes BSF-001)
    NEF->>BSF: GET /nbsf-management/v1/pcfBindings?ipv4Addr={ueIpv4Addr} (TS 29.521 §5.2.2.4)
    alt no binding for the UE IP
        BSF-->>NEF: 404 ProblemDetails (TS 29.521 §5.2.2.4.4)
        NEF-->>AF: 404 ProblemDetails (no serving PCF) (TS 29.522 §5.14.x)
    else binding found
        BSF-->>NEF: 200 PcfBinding{pcfFqdn|pcfIpEndPoints, pcfId, dnn, snssai} (TS 29.521 §6.2.6)
    end

    Note over NEF,PCF: map AsSessionWithQoS → Npcf_PolicyAuthorization (TS 29.514)
    NEF->>PCF: POST /npcf-policyauthorization/v1/app-sessions\nAppSessionContext{ascReqData:{aspId(afId), ueIpv4, medComponents{medType,fDescs}, qosReference}} (TS 29.514 §5.2.2.2)
    alt PCF authorizes
        PCF-->>NEF: 201 Created\nLocation: .../app-sessions/{appSessionId}\nAppSessionContext (TS 29.514 §5.2.2.2.3.1)
        NEF->>NEF: store subscription; map subscriptionId → {pcfUri, appSessionId, afId}
        NEF-->>AF: 201 Created\nLocation: .../subscriptions/{subscriptionId}\nAsSessionWithQoSSubscription (TS 29.522 §4.4.13.2.5)
    else PCF rejects authorization
        PCF-->>NEF: 403 ProblemDetails (TS 29.514 §5.2.2.2.4)
        NEF-->>AF: 403 ProblemDetails (propagated) (TS 29.522 §5.14.x)
    end

    Note over AF,NEF: AsSessionWithQoS — Delete (teardown)
    AF->>NEF: DELETE /3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions/{subscriptionId} (TS 29.522 §4.4.13.2.5)
    NEF->>PCF: DELETE /npcf-policyauthorization/v1/app-sessions/{appSessionId} (TS 29.514 §5.2.2.4)
    PCF-->>NEF: 204 No Content
    NEF-->>AF: 204 No Content
```

## Resources & Operations

Northbound API root: `{apiRoot}/3gpp-as-session-with-qos/v1`. PCF leg root:
`{apiRoot}/npcf-policyauthorization/v1`. All over HTTP/2 + mTLS (TS 29.500 §4.4.1); the
northbound NEF routes additionally require an OAuth2 bearer token (TS 29.522 §6).

### NEF northbound — AsSessionWithQoS (TS 29.522 §4.4.13)

| Op | Method | Route | Body → Response | Spec |
|---|---|---|---|---|
| Create | POST | `/3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions` | `AsSessionWithQoSSubscription` → **201** + `Location: …/subscriptions/{subscriptionId}` + body | TS 29.522 §4.4.13.2.5 |
| Read | GET | `/3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions/{subscriptionId}` | — → **200** `AsSessionWithQoSSubscription` / **404** | TS 29.522 §4.4.13.2.5 |
| Delete | DELETE | `/3gpp-as-session-with-qos/v1/{scsAsId}/subscriptions/{subscriptionId}` | — → **204 No Content** / **404** | TS 29.522 §4.4.13.2.5 |

> `{scsAsId}` is the SCS/AS (AF) identifier path segment. `{subscriptionId}` is minted by the
> NEF on Create (`uuid.NewString()`). A bare `GET …/{scsAsId}/subscriptions` collection read
> is **out of scope** for the baseline.

### PCF leg — Npcf_PolicyAuthorization (new, TS 29.514) — in scope (thin endpoint)

| Op | Method | Route | Body → Response | Spec |
|---|---|---|---|---|
| Create | POST | `/npcf-policyauthorization/v1/app-sessions` | `AppSessionContext` → **201** + `Location: …/app-sessions/{appSessionId}` + body | TS 29.514 §5.2.2.2 |
| Delete | DELETE | `/npcf-policyauthorization/v1/app-sessions/{appSessionId}` | — → **204 No Content** | TS 29.514 §5.2.2.4 |

> The PCF currently exposes `npcf-smpolicycontrol` / `npcf-ampolicycontrol` /
> `npcf-ue-policy-control` but **no** `npcf-policyauthorization`. This task adds a **thin**
> Create + Delete on `app-sessions` — enough to accept the NEF's authorization request,
> store it, and return `201`/`204`. The PCF SHOULD bind the resulting authorization to the
> serving SM policy association for the UE IP (reusing the existing
> `handleCreateSmPolicy` QoS-override path so the authorized `qosReference` becomes a
> DNN-scoped override). The **full** TS 29.514 app-session lifecycle (Update / Subscribe /
> Notify / event triggers) is **out of scope** (see Scope boundary).

## Information Elements

### `AsSessionWithQoSSubscription` (AF → NEF, POST body — TS 29.522 §5.14.2.1.2)

| IE | Type | M/C/O | Description / Spec |
|---|---|---|---|
| `ueIpv4Addr` | string (IPv4) | C | UE IPv4 address — the discovery key for BSF lookup. **One of** `ueIpv4Addr` / `ueIpv6Addr` / `macAddr` MUST be present |
| `ueIpv6Addr` | string (IPv6) | C | UE IPv6 address (alternative to `ueIpv4Addr`) — baseline targets IPv4 |
| `afAppId` | string | O | Application identifier as known to the AF (`afAppId`) |
| `flowInfo` | array(`FlowInfo`) | C | Description of the IP flow(s) the QoS applies to (`flowId`, `flowDescriptions[]`). TS 29.522 §5.x |
| `qosReference` | string | M | Reference to a pre-provisioned QoS profile (5QI-equivalent / operator-named QoS). TS 29.522 §5.14.2.1.2 |
| `altQoSReferences` | array(string) | O | Ordered alternative QoS references (fallback) — accepted, baseline uses the first only |
| `notificationDestination` | string (URI) | O* | AF callback URI for QoS notifications. **Stored but not used** in baseline (notifications are out of scope) |
| `dnn` | string | O | Target DNN — narrows the BSF discovery when the UE IP is ambiguous across DNNs |
| `snssai` | `Snssai` | O | Target S-NSSAI — narrows BSF discovery / PCF authorization |
| `supportedFeatures` | string (SupportedFeatures) | O | Negotiated optional features (TS 29.522 §6.x) |

> `notificationDestination` is mandatory in the full §5.14.2.1.2 model (QoS Notification
> Control). The baseline accepts and stores it but performs no callbacks — documented as a
> scope simplification, not a spec deviation in the request schema.

### `PcfBinding` fields consumed from BSF (TS 29.521 §6.2.6)

The NEF reads the Discovery response and uses only the routing + scoping fields:

| IE | Type | Use in NEF |
|---|---|---|
| `pcfFqdn` | string (FQDN) | Primary target for the PCF policy-authorization POST (SBI host) |
| `pcfIpEndPoints` | array(`IpEndPoint`) | Fallback target when `pcfFqdn` absent (IP + port + transport) |
| `pcfId` | string (NfInstanceId) | NRF correlation / logging |
| `dnn` | string | Passed through to the PCF app-session as scoping context |
| `snssai` | `Snssai` | Passed through to the PCF app-session as scoping context |

> **At least one of** `pcfFqdn` / `pcfIpEndPoints` is guaranteed present by BSF-001
> (the BSF always sets `pcfFqdn` + `pcfId`). The NEF prefers `pcfFqdn`.

### `AppSessionContext` (NEF → PCF, POST body — TS 29.514 §5.6.2.3)

The NEF builds `AppSessionContext.ascReqData` (`AppSessionContextReqData`) from the AF
request and the BSF binding:

| IE | Type | M/C/O | Mapped from |
|---|---|---|---|
| `aspId` | string | O | AF identifier (`afId` / `scsAsId`) — Application Service Provider id |
| `ueIpv4` | string (IPv4) | C | `AsSessionWithQoSSubscription.ueIpv4Addr` |
| `ueIpv6` | string (IPv6) | C | `AsSessionWithQoSSubscription.ueIpv6Addr` (when IPv6) |
| `medComponents` | map[medCompN → `MediaComponent`] | C | Built from `flowInfo`; each `MediaComponent` carries `medType` and `medSubComps`→`fDescs` (flow descriptions) |
| `medType` | `MediaType` enum | C | Media type per component (e.g. `AUDIO` / `VIDEO` / `DATA`); defaulted to `DATA` when AF gives only `flowInfo` |
| `qosReference` | string | M | `AsSessionWithQoSSubscription.qosReference` — the authorized QoS profile reference |
| `dnn` | string | O | From `PcfBinding.dnn` (or AF-supplied `dnn`) |
| `sliceInfo` | `Snssai` | O | From `PcfBinding.snssai` (or AF-supplied `snssai`) |
| `notifUri` | string (URI) | O | NEF's own callback URI (NOT the AF's) — baseline omits it (no PCF→NEF notifications) |
| `suppFeat` | string | O | Negotiated features |

## Error / Cause Cases

| Operation | Condition | HTTP Status | Cause (ProblemDetails) | Spec |
|---|---|---|---|---|
| Create | No UE address key (`ueIpv4Addr`/`ueIpv6Addr`/`macAddr` all absent) | **400** | `MANDATORY_IE_MISSING` | TS 29.522 §5.x, TS 29.500 §5.2.7.2 |
| Create | `qosReference` absent | **400** | `MANDATORY_IE_MISSING` | TS 29.522 §5.14.2.1.2 |
| Create | Malformed JSON body | **400** | `MANDATORY_IE_INCORRECT` | TS 29.500 §5.2.7.2 |
| Create | No PCF binding found for the UE IP (BSF Discovery 404) | **404** | `[VERIFY: Rel-17 Nbsf discovery-miss cause string not yet confirmed — see B-1 note]` | TS 29.521 §5.2.2.4.4 |
| Create | PCF rejects the authorization (403) | **403** | propagated from PCF `ProblemDetails` | TS 29.514 §5.2.2.2.4 |
| Get / Delete | Unknown `subscriptionId` | **404** | (no specific code; `ProblemDetails`) | TS 29.522 §4.4.13.2.5 |
| Any northbound | Missing / expired / wrong-scope bearer token | **401** | `UNAUTHORIZED` (no/invalid token) | TS 29.500 §5.2.7.2, TS 29.522 §6 |
| Any northbound | Valid token but AF not authorized for the operation | **403** | `MODIFICATION_NOT_ALLOWED` / `UNAUTHORIZED_AF` | TS 29.522 §6 |
| Any | Backend / store failure | **500** | `SYSTEM_FAILURE` | TS 29.500 §5.2.7.2 |

> **B-1 (carried from Session 11).** The BSF Discovery miss in BSF-001 returns `404` with a
> bare `ProblemDetails` (no defined error code in TS 29.521 §5.2.2.4.4). The NEF maps that to
> a northbound `404`. The **exact Rel-17 cause string** the NEF should surface to the AF for
> "no serving PCF for this UE IP" is **not yet verified**; recommend a placeholder cause
> (e.g. `PCF_BINDING_NOT_FOUND`) and `[VERIFY: confirm against TS29522 OpenAPI before coding]`.

## NF Interactions (SBI calls this procedure makes)

- **NEF → NRF**: `Nnrf_NFManagement_NFRegister`
  (`PUT /nnrf-nfm/v1/nf-instances/{nefId}` — `NFProfile{nfType: NEF, nfServices:[nnef-afsessionwithqos]}`)
  at startup, plus periodic `NFHeartBeat` (PATCH). Requires `NFType = "NEF"` in
  `nf/nrf/internal/registry/registry.go` — **add the enum if absent** (mirror how `BSF` was
  added for BSF-001).
- **AF → NRF**: `Nnrf_AccessToken_Get` (`POST /oauth2/token`, `client_credentials`,
  `scope=nnef-afsessionwithqos`) to obtain the bearer token (HS256 JWT, the existing model
  the other NFs use). The NEF **verifies** the token on each northbound request.
- **NEF → BSF**: `Nbsf_Management_Discovery`
  (`GET /nbsf-management/v1/pcfBindings?ipv4Addr=…`) — consumes BSF-001 unchanged. The NEF
  discovers the BSF via NRF (`Nnrf_NFDiscovery`, `target-nf-type=BSF`); no hardcoded BSF host.
- **NEF → PCF**: `Npcf_PolicyAuthorization_Create`
  (`POST /npcf-policyauthorization/v1/app-sessions`) — target host comes from the
  `PcfBinding` (`pcfFqdn` / `pcfIpEndPoints`), **not** from NRF discovery (the BSF already
  named the *serving* PCF instance, which NRF discovery cannot disambiguate per-UE).
- **NEF → PCF**: `Npcf_PolicyAuthorization_Delete`
  (`DELETE /npcf-policyauthorization/v1/app-sessions/{appSessionId}`) on AF Delete.

## Implementation Notes

State machine / store
- New NF under `nf/nef/` copied from `nf/_template/` (read its CLAUDE.md first).
  `cmd/nef/main.go`: config → logger → SBI server → NRF registration → signals → shutdown.
  All logic in `internal/` (`internal/config`, `internal/server`).
- `internal/server/server.go`: HTTP/2 + mTLS SBI server with three northbound handlers
  (`handleCreateSubscription` POST, `handleGetSubscription` GET, `handleDeleteSubscription`
  DELETE) plus the OAuth2 verification middleware.
- Subscription store: in-memory map is sufficient for the baseline (parity with BSF's initial
  store), keyed by `subscriptionId` → `{scsAsId, afId, ueIpv4Addr, qosReference, pcfUri,
  appSessionId}`. A Postgres table is **not required** for NEF-001 (no restart-survival
  acceptance criterion); note it as a future increment if persistence is wanted.
- Clients: `internal/server/bsf_client.go` (`Discover(ctx, ipv4Addr) → PcfBinding`) and
  `internal/server/pcf_client.go` (`CreateAppSession` / `DeleteAppSession`). The BSF host is
  resolved via NRF; the PCF host is taken from the discovered `PcfBinding`.

Port assignment (recommendation — compose wiring deferred, see Scope boundary)
- **SBI port `8011`** — prior NFs: SMSF=`8009`, BSF=`8010`; `8011` is free (verified: no
  match in `docker-compose.yml` / per-NF `config/dev.yaml`).
- **Metrics port `9112`** — verified: SMSF=`9110`, BSF=`9111` are taken (`docker-compose.yml`
  lines 447–448, `nf/bsf/config/dev.yaml`). `9112` is the next free port. (Note: the task
  descriptor suggested `9111`, but `9111` is already BSF's metrics port — use **`9112`**.)
- Prometheus scrape target `nef:9112` (`observability/prometheus/prometheus.yml`) is part of
  the **deferred** compose-wiring surface — not added in this task.

PCF leg (new thin endpoint — acceptance criterion 2)
- `nf/pcf/internal/server/server.go`: add `handleCreateAppSession`
  (`POST /npcf-policyauthorization/v1/app-sessions`) and `handleDeleteAppSession`
  (`DELETE …/{appSessionId}`). Register the `nnef`-facing service in the PCF's NF profile is
  **not** needed (the PCF service is `npcf-policyauthorization`, consumed by NEF).
- On Create: mint `appSessionId`, store the `AppSessionContext`, and translate the authorized
  `qosReference` into the existing **DNN-scoped QoS override** path (reuse the
  `handleSetQoSOverride` / `handleCreateSmPolicy` override machinery so the authorized QoS
  actually reaches the UE's SM policy). Best-effort binding to the serving SM policy by UE IP.
- On Delete: drop the stored app-session and remove the associated override.

OAuth2 (acceptance criterion 3)
- Reuse the existing NRF HS256 bearer-token model (same posture as the other NFs' SBI client
  auth). The northbound middleware verifies: signature, `exp`, and `scope` includes
  `nnef-afsessionwithqos`. The AF is identified by the `{scsAsId}` path segment plus an
  `afId` claim/field; log `af_id` on every northbound request.
- CAPIF / TS 33.122 onboarding is **out of scope** — bearer-token verification only.

Logging (root CLAUDE.md format)
- NEF logs: `nf=NEF`, `procedure=AsSessionWithQoSCreate|AsSessionWithQoSGet|AsSessionWithQoSDelete`,
  `interface=Nnef` (northbound) / `Nbsf` (discovery, `direction=OUT`) / `Npcf`
  (authorization, `direction=OUT`), `spec_ref="TS 29.522 §4.4.13"` /
  `"TS 29.521 §5.2.2.4"` / `"TS 29.514 §5.2.2.2"`, conditional `af_id`, `scs_as_id`,
  `subscription_id`, `app_session_id`, `ue_ipv4`, `pcf_id`, `result` (`OK`/`REJECT`), `cause`.
- PCF leg logs: `procedure=PolicyAuthorizationCreate|PolicyAuthorizationDelete`,
  `interface=Npcf`, `direction=IN`, `app_session_id`, `spec_ref="TS 29.514 §5.2.2.x"`.

Validation approach (same posture as BSF-001 — no live UERANSIM)
- **Unit tests** (in-process): northbound Create returns `201` + `Location`; missing UE addr
  → `400`; missing `qosReference` → `400`; BSF discovery miss → `404`; PCF `403` propagated;
  unknown `subscriptionId` on Get/Delete → `404`; missing/invalid token → `401`/`403`.
- **godog functional** (`nf/nef/tests/features/network-exposure.feature`, in-process server
  with **mock NRF / mock BSF / mock PCF**): Create → BSF Discovery returns a `PcfBinding` →
  NEF POSTs `AppSessionContext` to the mock PCF → `201`; Delete drives the PCF app-session
  Delete; discovery-miss path returns `404`. PCF-side: the thin `app-sessions` Create/Delete
  is covered by a PCF functional test reusing `nf/pcf/internal/server`.
- **No live UERANSIM**: Nnef/Nbsf/Npcf is SBA-only and there is **no AF in UERANSIM**, so
  there is nothing for a UE/gNB to exercise. The full live chain becomes meaningful only with
  a real/mock AF and compose wiring (the deferred increment).

[VERIFY: northbound discovery-miss cause string (B-1) and the exact `AsSessionWithQoSSubscription`
required-field set — confirm against the Rel-17 `TS29522_AsSessionWithQoS.yaml` before coding.]
