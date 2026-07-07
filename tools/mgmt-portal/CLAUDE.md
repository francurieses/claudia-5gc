# CLAUDE.md — 5GC Management Portal (`tools/mgmt-portal`)

> Read the root `CLAUDE.md` for global conventions.
> This module's stack is a deliberate exception to NF restrictions.

## 1. What It Is

Web interface (port **8080**) to operate and monitor the 5GC. Development tool, not a 3GPP NF.
Access: `http://localhost:8080` after `make portal`.

## 2. Stack (Authorized Exception)

| Layer | Technology |
|------|-----------|
| Frontend | React 18 + TypeScript + Vite 6 + Tailwind CSS |
| API client | TanStack Query (`@tanstack/react-query`) |
| Icons | `lucide-react` |
| Go Router | `github.com/go-chi/chi/v5` (forbidden in NFs) |
| WebSocket | `github.com/gorilla/websocket` (forbidden in NFs) |
| PostgreSQL | `github.com/jackc/pgx/v5` |
| Docker SDK | `github.com/docker/docker/client` via `/var/run/docker.sock:ro` |
| Build | Multi-stage Dockerfile: node:22 → golang:1.26.2 → alpine:3.21 |
| Embed | `//go:embed static/` in `internal/assets/assets.go` |

## 3. File Structure

```
tools/mgmt-portal/
├── cmd/mgmt-portal/main.go
├── internal/
│   ├── api/             router.go · helpers.go · subscribers.go · slices.go · services.go
│   │                    sessions.go · nfstatus.go · logs.go · metrics.go · pcap.go · ueransim.go · packetrusher.go
│   ├── docker/client.go
│   ├── store/store.go
│   ├── nrf/client.go
│   ├── prometheus/client.go
│   ├── config/nfconfig.go
│   └── assets/assets.go + static/
└── web/src/
    ├── App.tsx
    ├── pages/           Dashboard · Subscribers · Slices · Services · Sessions · UERANSim · PacketRusher · Logs · PCAP
    ├── components/      NFStatusCard · StatCard · PageHeader · Badge
    └── lib/api.ts
```

## 4. Full REST API

```
# Subscribers
GET/POST /api/v1/subscribers
GET/PUT/DELETE /api/v1/subscribers/{supi}
# Per-subscriber RFSP (proxies PCF AM policy override — TS 38.413 §9.3.1.27)
GET    /api/v1/subscribers/{supi}/rfsp     # {"supi","rfsp","source":"override"|"default"}
PUT    /api/v1/subscribers/{supi}/rfsp     # body {"rfsp":1-256} → PCF override + NW dereg to re-apply
DELETE /api/v1/subscribers/{supi}/rfsp     # clear override → revert to operator default + NW dereg

# Slices  (body: {sst, sd, restart:bool})
GET /api/v1/slices
POST /api/v1/slices                # restart=true restarts amf/smf/nssf after save
DELETE /api/v1/slices/{sst}/{sd}

# DNNs  (body: {name, ue_ip_pool, n6_network, description, restart:bool})
GET /api/v1/dnns                   # merged view from operator.yaml + UPF config; includes next_ue_pool/next_n6_network suggestions
POST /api/v1/dnns                  # creates DNN in operator.yaml+SMF+UPF configs, creates Docker network, connects UPF, restarts if restart=true
PUT /api/v1/dnns/{name}            # updates description only (no restart required); body: {description}
DELETE /api/v1/dnns/{name}?restart=true  # removes from all configs, disconnects Docker network, removes network, restarts if restart=true

# Services
GET /api/v1/services
POST /api/v1/services/{name}/start|stop|restart

# NF Status
GET /api/v1/nf-status              # NRF discovery + /healthz + /metrics polling

# Sessions
GET /api/v1/sessions               # smf_sessions WHERE ue_ip != ''
GET /api/v1/ue-contexts            # amf_ue_contexts

# Metrics
GET /api/v1/metrics/summary        # Prometheus instant queries

# PCAP
GET /api/v1/pcap/status
POST /api/v1/pcap/{nf}/start|stop|pause|resume|rotate
GET /api/v1/pcap/{nf}/files
GET /api/v1/pcap/{nf}/files/{filename}    # Content-Disposition: attachment

# UERANSIM
GET /api/v1/ueransim/status
POST /api/v1/ueransim/nr-cli       # {container, supi, command}
POST /api/v1/ueransim/ping         # {container, ue_ip, target, count}
GET /api/v1/ueransim/scenarios     # state of all 3 scenarios (standard|slices|profile-a)
POST /api/v1/ueransim/scenarios/{scenario}/start   # stops conflicts, starts scenario
POST /api/v1/ueransim/scenarios/{scenario}/stop

# PacketRusher mobility testing
GET  /api/v1/packetrusher/status           # state of both scenario containers
POST /api/v1/packetrusher/{scenario}/start  # scenario: "xn" | "n2"
POST /api/v1/packetrusher/{scenario}/stop
POST /api/v1/packetrusher/{scenario}/pause
POST /api/v1/packetrusher/{scenario}/resume

# QoS / PDU sessions (proxies SMF /nsmf-management + UDM Nudm_SDM via mTLS client)
GET  /api/v1/qos/sessions                  # live SMF session store with 5QI/source/AMBR/state
GET  /api/v1/qos/sessions/{psi}?supi=      # session detail + QoS flows + PFCP QER view
POST /api/v1/qos/sessions/{psi}/modify     # {"5qi","reason","supi"?} → NW-initiated modification (TS 23.502 §4.3.3.2)
GET  /api/v1/qos/subscription/{supi}       # UDM sm-data (subscribed default QoS)
POST /api/v1/qos/nw-sessions               # NW-triggered ADDITIONAL PDU session (URSP steering — TS 23.503 §6.6.2)
                                           # {"supi","app","dnn","sst","sd","5qi","ambr_uplink"?,"ambr_downlink"?,"app_fqdns"?}
                                           # orchestrates: PCF DNN-scoped override → URSP rule store →
                                           # AMF UCU push → nr-cli ps-establish (simulated URSP eval) → SMF verify
                                           # returns: {"success","steps"[],"pdu_session_id","ue_ip","5qi","qos_source"}

# Policies (URSP — TS 24.526 / TS 29.525)
GET/POST /api/v1/policies                      # per-subscriber policy CRUD
GET/PUT/DELETE /api/v1/policies/{id}
POST /api/v1/policies/push/{supi}              # trigger AMF UCU for registered UE

# Policy Templates (portal-managed, seeded with 4 slice defaults)
GET /api/v1/policy-templates                   # list templates
POST /api/v1/policy-templates                  # create template
GET/PUT/DELETE /api/v1/policy-templates/{id}
POST /api/v1/policy-templates/{id}/apply       # body: {"supi":"imsi-..."} → writes per-subscriber
                                               # policy to subscription_policy + triggers AMF UCU
                                               # returns: {"status":"pushed"} | {"status":"stored","warning":"..."}

# WebSocket
WS /ws/logs/{container}?tail=N

# Health
GET /api/v1/health
```

## 5. Pages

| Page | Functionality |
|--------|--------------|
| Dashboard `/` | 4 KPI cards + grid of 9 NF cards (NRF/healthz/metrics) + table of latest 8 active PDU sessions |
| Subscribers `/subscribers` | CRUD from `subscription_auth` JOIN `subscription_am`; create/edit form with per-slice DNN picker (only DNNs configured in operator.yaml shown); DNN stored in `subscription_am.snssais` JSONB as `{sst, sd, dnn}`; cascade delete. **SQN is read-only on edit** — it is network-managed (UDM increments it per auth); `PUT` preserves the DB value (`UpsertSubscriber(…, preserveSQN=true)`) because writing a stale SQN back breaks UERANSIM re-registration (SMC integrity failure, no AUTS resync in v3.2.8). Updates reject empty `k`/`opc`. Every update triggers NW-initiated dereg with "re-registration required" (no 5GMM cause) so the UE re-registers automatically (needs UERANSIM patch 0050). **RFSP column**: per-subscriber inline box (1-256) — sets a PCF AM-policy override and triggers NW-initiated re-registration so the new IndexToRFSP reaches the gNB; "(default)" badge when no override, purple when overridden; reset button reverts to operator default. |
| Slices `/slices` | Two sections: (1) S-NSSAI list from AMF/SMF/NSSF YAML; add SST+SD with restart checkbox. (2) DNN management — add/edit description/delete DNNs with auto-assigned UE IP pool, N6 Docker network, UPF TUN device; restart SMF+UPF after changes; next_ue_pool/next_n6_network auto-suggested. |
| Services `/services` | Start/Stop/Restart per container; status and uptime (polling 5 s) |
| Sessions `/sessions` | PDU sessions (`smf_sessions WHERE ue_ip != ''`) + UE contexts (`amf_ue_contexts`) |
| QoS `/qos` | Live PDU session table from the SMF (5QI colour-coded by TS 23.501 category, source, AMBR, state, 10 s auto-refresh); **Modify QoS** drawer (grouped 5QI selector, required reason, confirmation, toast) triggering NW-initiated modification; **Subscription inspector** (UDM defaultQos vs session 5QI diff); collapsible **E2E validation panel** (list → subscription → modify → verify → revert); **NW-Triggered PDU Session panel** (simulated app-detection event: UE picker, app presets with 5QI mapping, DNN/S-NSSAI/AMBR form, live 5-step orchestration checklist — establishes an *additional* PSI via URSP steering, `docs/procedures/nw-triggered-pdu-session.md`) |
| UERANSIM `/ueransim` | **Scenarios panel** (Standard / Multi-Slice / SUCI Profile A) — one-click Start/Stop with conflict resolution; container grid; registered UE table; ping dialog (`ping -I <ue_ip>`); nr-cli dialog; inline logs |
| PacketRusher `/packetrusher` | Xn HO and N2 HO scenario cards; Start/Stop/Pause/Resume per scenario; tabbed log viewer (PacketRusher + AMF + SMF); live mobility-event checklist |
| Policies `/policies` | **Policy Templates** section: 4 slice-colour-coded cards (Internet/Gold/Silver/Bronze), each shows JSON rules, 3GPP spec reference table, Edit button, **Apply to UE** button (picks registered UE, optional rule customisation, shows delivery path). **Per-Subscriber** section: live list of active URSP overrides with Push button. |
| Logs `/logs` | WebSocket streaming Docker logs; JSON parsing; filter; pause/resume; export |
| PCAP `/pcap` | Cards per sidecar; Start/Stop/Rotate; file list with Download button |

**SUPI→container heuristic** (`guessUEContainer` in `ueransim.go`): IMSI `...001` → `ueransim-ue-internet`, `...002` → `gold`, `...003` → `silver`, `...004` → `bronze`, rest → `ueransim-ue`. If container names change, update the map there.

## 6. PostgreSQL — Relevant Schema (Gotchas)

```sql
-- smf_sessions (written by SMF)
sm_context_ref TEXT PRIMARY KEY
supi TEXT, dnn TEXT, ue_ip TEXT, ul_teid BIGINT, seid BIGINT, sst INT, sd TEXT
created_at TIMESTAMPTZ DEFAULT NOW()
-- Portal: WHERE ue_ip IS NOT NULL AND ue_ip != ''

-- amf_ue_contexts (written by AMF)
supi TEXT PRIMARY KEY
tmsi BIGINT          -- nullable; use COALESCE(tmsi, 0)
gmm_state INT
context_json JSONB
registered_at TIMESTAMPTZ   -- column is "registered_at", NOT "created_at"
last_activity TIMESTAMPTZ

-- subscription_am (written by UDR / portal)
subscribed_ue_ambr_uplink / subscribed_ue_ambr_downlink   -- NOT "ambr_ul/dl"
snssais JSONB   -- [{sst, sd}, ...]

-- subscription_policy (written by UDR and portal — shared)
id TEXT PRIMARY KEY DEFAULT gen_random_uuid()
supi TEXT   -- NULL = operator default
precedence INT, rules_json JSONB, updated_at TIMESTAMPTZ

-- portal_policy_templates (portal-only, created by store.Migrate on startup)
id TEXT PRIMARY KEY DEFAULT gen_random_uuid()
name TEXT, description TEXT, slice_name TEXT  -- internet|gold|silver|bronze
precedence INT, rules_json JSONB, updated_at TIMESTAMPTZ
-- Seeded with 4 defaults (Internet/Gold/Silver/Bronze) if table is empty
```

## 7. Local Development (Without Docker)

```bash
# Terminal 1 — frontend HMR
cd tools/mgmt-portal/web && npm install && npm run dev   # http://localhost:5173

# Terminal 2 — backend
cd tools/mgmt-portal
DATABASE_URL=postgresql://5gc:5gc@localhost:5432/5gc \
NRF_URL=http://localhost:8000 \
PROMETHEUS_URL=http://localhost:9090 \
go run ./cmd/mgmt-portal
# vite.config.ts has proxy /api → :8080 and /ws → ws://:8080
```

## 8. Build and Deploy

```bash
make docker-portal   # build image
make portal          # up-obs + docker-compose up mgmt-portal
```

`.dockerignore` excludes `web/node_modules` (avoids WSL2/Linux permission conflicts).

## 9. Environment Variables

| Variable | Description | Default docker-compose |
|----------|-------------|----------------------|
| `DATABASE_URL` | PostgreSQL DSN | `postgresql://5gc:5gc@postgres:5432/5gc` |
| `NRF_URL` | NRF base URL | `http://nrf:8000` |
| `PROMETHEUS_URL` | Prometheus URL | `http://prometheus:9090` |
| `SMF_URL` | SMF base URL (mTLS SBI; mgmt API shares the listener) | `https://smf:8004` |
| `UDM_URL` | UDM base URL for sm-data lookups | `https://udm:8003` |
| `PCF_URL` | PCF base URL for SM policy QoS overrides (NW-triggered sessions) | `https://pcf:8006` |
| `NF_CONFIGS_PATH` | NF YAML config directory | `/app/nf-configs` |
| `OPERATOR_CONFIG_PATH` | Path to shared operator.yaml (must be writable for DNN management) | `/etc/5gc/operator.yaml` |
| `LISTEN_ADDR` | Bind address | `:8080` |

## 10. Graceful degradation

- `Store == nil` → queries return `[]`
- `Docker == nil` → container operations return 503
- `NRF == nil` → `/nf-status` empty
- `Prometheus == nil` → `/metrics/summary` returns zeros

## 11. Technical Notes

- NRF client uses `InsecureSkipVerify: true` — dev tool, not NF.
- `go.work` includes `./tools/mgmt-portal` for builds from workspace root.
- PCAP signals (pause/resume/rotate) are stubs — implement with `Docker.Exec` + `kill -SIG`.
- Node.js only needed on WSL for local build; Docker stage 1 handles it.
