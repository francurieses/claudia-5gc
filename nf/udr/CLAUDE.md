# CLAUDE.md — UDR (Unified Data Repository)

> Read the root `CLAUDE.md` first for global conventions.

## 1. Function

UDR is the subscription, policy, and exposure data repository. UDM, PCF, and NEF read/write to UDR. Contains no business logic — it's just persistence.

**Primary specifications:**
- **TS 29.504** — Nudr_DataRepository (Stage 3)
- TS 29.505 — Subscription data types

## 2. Reference Points

| Interface | Peer | Protocol | Spec |
|---|---|---|---|
| N35 | UDM | Nudr SBI | TS 29.504 |
| N36 | PCF | Nudr SBI | TS 29.504 |
| N37 | NEF | Nudr SBI | TS 29.504 |

## 3. Implemented Endpoints

| Method | Route | Description |
|---|---|---|
| GET | `/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription` | Auth subscription |
| PATCH | `/nudr-dr/v2/subscription-data/{supi}/authentication-data/authentication-subscription` | Update SQN |
| GET | `/nudr-dr/v2/subscription-data/{supi}/{plmn}/provisioned-data/am-data` | AM subscription |
| GET/PUT | `/nudr-dr/v2/subscription-data/{supi}/{plmn}/provisioned-data/sm-data` | SM subscription (per-slice `5gQosProfile` + `sessionAmbr`, TS 29.503 §6.1.6.2.7) |
| PUT | `/nudr-dr/v2/subscription-data/{supi}/context-data/amf-3gpp-access` | AMF context |
| POST | `/nudr-internal/v1/subscribers/{supi}/sync-sm-data` | **Internal, not 3GPP.** Re-derives sm-data from the slices in am-data. The management portal provisions slices by writing `subscription_am` directly; this keeps the slice→QoS mapping (`store.BuildSMSubscriptions`) owned by the UDR instead of duplicated in the portal. |

## 4. Implementation Status

| Function | Status |
|---|---|
| In-memory store | ✅ Functional (fallback without DATABASE_URL) |
| Auth subscription CRUD | ✅ Functional |
| AM subscription GET | ✅ Functional |
| AMF context registration | ✅ Functional |
| PostgreSQL persistence | ✅ Implemented (pgx/v5, auto-migrate) |

## 5. Store — PostgreSQL (Default) / In-Memory (Fallback)

### Runtime Selection

If the `DATABASE_URL` environment variable is present, UDR uses the PostgreSQL store (`store.Postgres`).
Otherwise, it uses `store.InMemory` with a warning log (dev only without Docker).

```
DATABASE_URL=postgres://5gc:5gc-dev@postgres:5432/5gc?sslmode=disable
```

The docker-compose already injects this variable. Change `sslmode=require` for production.

### Auto-Migration

`store.NewPostgres` runs embedded SQL files in `internal/store/migrations/` on startup (idempotent — uses `CREATE TABLE IF NOT EXISTS`).

### Schema

| Table | Description |
|---|---|
| `subscription_auth` | Authentication credentials (K, OPc, AMF, SQN, algorithm) |
| `subscription_am` | Access and mobility subscription (NSSAI, AMBR) |
| `subscription_smf` | SMF selection info (S-NSSAI → DNN) |
| `subscription_sm` | Session management subscription — JSONB array of per-slice entries with subscribed default 5QI/ARP/AMBR |

JSONB columns for arrays (`snssais`, `gpsis`, `subscribed_snssai_infos`) — allow schema evolution without destructive migrations.

## 6. In-Memory Store (Fallback)

`internal/store/InMemory` — data in maps protected by `sync.RWMutex`. Active only when `DATABASE_URL` is not configured.

**Seeded subscribers** (loaded in `main.go` via `store.SeedTestSubscriber`, valid for both backends):
```
SUPI:  imsi-001010000000001  (+ 002, 003, ... per UE_COUNT)
K:     465B5CE8B199B49FAA5F0A2EE238A6BC
OPc:   E8ED289DEBA952E4283B54E88E6183CA
AMF:   8000
SQN:   000000000001
Alg:   milenage
```
MCC=001, MNC=01. Configured to match UERANSIM UEs in `config/ueransim/ue.yaml`.

**Multi-UE**: `main.go` seeds `UE_COUNT` subscribers (env var, default 1) with
consecutive IMSIs starting from `imsi-001010000000001`, all with the same
Milenage key. This mirrors how UERANSIM `nr-ue -n N` generates UEs. Controlled by
`make ueransim UE_COUNT=N` from the root.

To add subscribers in dev: increase `UE_COUNT`, modify `SeedTestSubscriber`,
or add a provisioning route.

## 7. Commands

```bash
make -C nf/udr build
make -C nf/udr test
make -C nf/udr docker
```
