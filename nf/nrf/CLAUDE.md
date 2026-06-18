# CLAUDE.md — NRF (Network Repository Function)

> Read the root `CLAUDE.md` first for global conventions.

## 1. Function

NRF is the **service registry and discovery** of the 5GC. Every NF registers with NRF on startup and queries NRF to discover other NFs.

**Primary specifications:**
- TS 23.501 §6.2.6 — Functional description
- TS 23.502 §4.17 — Procedures
- **TS 29.510** — Stage 3, this is the primary document
- TS 33.501 §13 — SBA security (NRF as OAuth2 Authorization Server)

## 2. Implemented SBI Services

| Service | Operation | Route | Spec |
|---|---|---|---|
| `nnrf-nfm` | NFRegister | `PUT /nnrf-nfm/v1/nf-instances/{nfInstanceId}` | §5.2.2.2 |
| `nnrf-nfm` | NFUpdate | `PATCH /nnrf-nfm/v1/nf-instances/{nfInstanceId}` | §5.2.2.3 |
| `nnrf-nfm` | NFDeregister | `DELETE /nnrf-nfm/v1/nf-instances/{nfInstanceId}` | §5.2.2.4 |
| `nnrf-nfm` | NFProfileRetrieve | `GET /nnrf-nfm/v1/nf-instances/{nfInstanceId}` | §5.2.2.5 |
| `nnrf-nfm` | NFListRetrieval | `GET /nnrf-nfm/v1/nf-instances` (`?detail=true` inlines profiles) | §5.2.2.6 |
| `nnrf-disc` | NFDiscover | `GET /nnrf-disc/v1/nf-instances` | §5.3.2.2 |

## 3. Heartbeat and Eviction Status (Implemented, May 2026)

### Heartbeat (TS 29.510 §5.2.2.3.4)

- The `PATCH /nnrf-nfm/v1/nf-instances/{id}` handler detects if the body is a JSON Patch array (starts with `[`): if so, calls `reg.Heartbeat(id)` → updates `lastSeen` without modifying the profile. Otherwise, does full-replace (previous behavior).
- The response profile of `PUT` (Register) always includes `heartBeatTimer = 60` seconds.
- `shared/nrf/Client.RegisterAndStartHeartbeat` registers the NF and starts a goroutine sending heartbeats every `0.8 × heartBeatTimer`.

### Eviction

- `InMemory.StartEviction(ctx, timeout)` starts a goroutine that ticks every `timeout/2`.
- On each tick, iterates profiles and removes those with `now - lastSeen > timeout`.
- Default in NRF, `timeout = 2 × HeartbeatTimeoutSec` (config, default 90 s → 180 s eviction window).
- `WARN` log with `procedure=NFEviction` and `last_seen_ago_s` when an NF is evicted.

### NRF Client in NFs

`shared/nrf/client.go` — import from any NF's main module:
```go
nrfClient := nrf.New(cfg.Peers.NRFAddress, httpClient, logger)
nrfClient.RegisterAndStartHeartbeat(ctx, profile, 45*time.Second)
```
Currently wired in AMF. TODO: SMF, UDM, AUSF, PCF.

## 4. Redis Backend (Implemented, May 2026)

The NRF selects the registry backend on startup:

- If `REDIS_URL` is configured → `RedisRegistry` (`nf/nrf/internal/registry/redis.go`).
- Otherwise → `InMemory` (fallback for dev without Redis).

**Redis key**: `nrf:nf:{nfInstanceId}` → JSON of NFProfile with TTL = `HeartbeatTimeoutSec`.
- `Register`: `SET key json EX ttl`
- `Heartbeat`: `EXPIRE key ttl` (restarts TTL; native Redis eviction)
- `Update`: `SET key json KEEPTTL` (preserves remaining TTL)
- `Discover`: `SCAN nrf:nf:* + MGET + filter`

The eviction goroutine (`StartEviction`) only activates for `InMemory`; `RedisRegistry` doesn't need it because Redis expire handles eviction automatically.

## 5. TODO (Roadmap)

- [x] NFStatusSubscribe/Unsubscribe (POST/DELETE /nnrf-nfm/v1/subscriptions)
- [x] NFStatusNotify (async POST to notificationUri on NF_REGISTERED/NF_DEREGISTERED/NF_PROFILE_CHANGED)
- [x] NFListRetrieval (§5.2.2.6) — ids by default, full profiles with `?detail=true`
- [ ] SCP-aware discovery (Model D delegated discovery).
- [ ] OAuth2 scope validation in discover (filters by authorized NFs).

## 6. Commands

```bash
make build        # build binary
make test         # unit tests
make docker       # image 5gc/nrf:dev
make run          # run locally with config/dev.yaml
```

## 7. Logging — Mandatory Fields

Beyond globals, every NRF procedure log must include:

- `procedure`: `NFRegister`, `NFUpdate`, `NFDeregister`, `NFDiscover`, `NFStatusNotify`
- `target_nf_instance_id`: NF object of the operation
- `target_nf_type`: type of NF object

## 8. Validate Against TS 29.510

To add a new endpoint:

1. Locate the corresponding section §5.x in TS 29.510 v17.
2. Download/update the OpenAPI YAML: `scripts/sync-openapi.sh`. NRF's are `TS29510_Nnrf_NFManagement.yaml` and `TS29510_Nnrf_NFDiscovery.yaml`.
3. Implement handler in `internal/server/server.go`.
4. Add unit test in `internal/registry/registry_test.go` if touching registry logic.
5. Validate with `tools/compliance-checker` that the response complies with the OpenAPI schema.

## 9. Don't Do

- ❌ DO NOT allow registration without mutual TLS (except explicit dev profile).
- ❌ DO NOT make internal discovery synchronous (any discovery call is via API).
- ❌ DO NOT store credentials/secrets in the NFProfile (that's UDR's job).
