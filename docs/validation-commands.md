# Validation Commands — 5GC Rel-17

Reference guide for bringing up the stack, executing 3GPP procedures, and
verifying the status of each feature with UERANSIM v3.2.8.

---

## 1. Stack startup

```bash
# Complete core + observability + UERANSIM (1 UE)
make ueransim

# With N UEs (increments IMSI from 001010000000001, seeds N subscribers in UDR)
make ueransim UE_COUNT=3

# Restart only UERANSIM (gNB + UE) without rebuilding core
make ueransim-only

# Core only (without UERANSIM)
make up-obs

# Stop everything and clean volumes
make down
```

> **IMPORTANT**: Changing `UE_COUNT` requires `make ueransim` (not `ueransim-only`)
> to reseed the UDR with the correct number of subscribers.

---

## 2. Verify all containers are up

```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "NAME|nrf|amf|smf|upf|ausf|udm|udr|pcf|ueransim|jaeger|prometheus|grafana"
```

Expected state: all `Up` and without recent restarts (`Restarting` indicates failure).

---

## 3. Registration (Initial Registration)

### Check UE state

```bash
# MM / CM / RM state
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "status"
```

Expected result:
```
rm-state: RM-REGISTERED
mm-state: MM-REGISTERED/NORMAL-SERVICE
cm-state: CM-CONNECTED
```

### View UE information (SUPI, IMEI, capabilities)

```bash
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "info"
```

### View active NAS timers

```bash
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "timers"
```

### Multi-UE: list all available nodes

```bash
docker exec ueransim-ue nr-cli -d
# Expected output with UE_COUNT=3:
# imsi-001010000000001
# imsi-001010000000002
# imsi-001010000000003
```

---

## 4. PDU Sessions

### List active sessions

```bash
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-list"
```

Expected result:
```
PDU Session1:
 state: PS-ACTIVE
 session-type: IPv4
 apn: internet
 address: 10.60.0.X
 ambr: up[100Mb/s] down[100Mb/s]
```

### Establish new PDU Session manually

```bash
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish IPv4 --sst 1 --sd 1 --dnn internet"
```

> The initial session is established automatically when the UE registers (config `sessions:` in `ue.yaml`).

### Release a PDU Session (UE-initiated release)

```bash
# Release PSI 1
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-release 1"

# Release all sessions
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-release-all"
```

Expected UE logs:
```
[nas] Sending PDU Session Release Request for PSI[1]
[nas] PDU Session Release Command received
[nas] Performing local release of PDU session[1]
```

> The UE auto-reestablishes the session if configured in `sessions:` in the yaml.

---

## 5. Data plane — ping

The UE's TUN interface (`uesimtun0`, `uesimtun1`, ...) appears upon completing
the PDU Session Establishment. Traffic flows: UE → gNB (GTP-U) → UPF → N6 internet.

```bash
# Ping to internet (via UPF N6 + iptables MASQUERADE)
docker exec ueransim-ue ping -I uesimtun0 8.8.8.8 -c 5
docker exec ueransim-ue ping -I uesimtun0 1.1.1.1 -c 5

# Ping to UPF TUN (N6 local, faster, validates data plane without internet)
docker exec ueransim-ue ping -I uesimtun0 172.30.3.100 -c 5

# Multi-UE: each UE has its own interface
docker exec ueransim-ue ping -I uesimtun0 8.8.8.8 -c 3   # UE1
docker exec ueransim-ue ping -I uesimtun1 8.8.8.8 -c 3   # UE2

# Verify IP assigned by SMF on the TUN interface
docker exec ueransim-ue ip addr show uesimtun0
```

Expected result: 0% packet loss, RTT ~1-5ms (local UPF), ~10-50ms (internet).

### If ping fails

1. Verify PDU session is `PS-ACTIVE`: `ps-list`
2. Verify TUN interface exists: `docker exec ueransim-ue ip link show`
3. Check UPF logs: `docker logs upf 2>&1 | tail -20`
4. Verify UPF has forwarding route: `docker exec upf ip route`
5. Check iptables MASQUERADE: `docker exec upf iptables -t nat -L POSTROUTING -n -v`

---

## 6. Deregistration — TS 23.502 §4.2.2.3.2

### 6.1 Normal deregistration (AMF sends Deregistration Accept)

```bash
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "deregister normal"
```

Expected UE logs:
```
[nas] Starting de-registration procedure due to [NORMAL]
[nas] Performing local release of PDU session[1]
[nas] UE switches to state [MM-DEREGISTER-INITIATED]
[nas] Deregistration Accept received
[nas] UE switches to state [MM-DEREGISTERED]
```

Expected AMF logs (in order):
```bash
docker logs amf --since=30s | jq 'select(.procedure=="Deregistration")'
```
```json
{"procedure":"Deregistration","msg":"Deregistration Request received","switch_off":false}
{"procedure":"Deregistration","msg":"sending NAS message","message_type":"46"}
{"procedure":"Deregistration","msg":"UE deregistered","result":"OK"}
```

### 6.2 Switch-off (UE powers off — AMF does not send Accept)

```bash
# Option A: explicit switch-off command
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "deregister switch-off"

# Option B: stop the container directly
docker stop ueransim-ue
```

On switch-off the AMF **does not** send Deregistration Accept (0x46). Session teardown and
UDM UECM deregistration are performed the same way.

```bash
docker logs amf --since=30s | jq 'select(.procedure=="Deregistration")'
# → switch_off: true → "sending NAS message" with message_type "46" does NOT appear
```

### 6.3 Verify PDU session teardown in SMF

```bash
docker logs smf --since=30s | jq 'select(.msg | contains("delete") or contains("Delete") or contains("Release"))'
# → should show "SM context deleted" or similar for each active PDU session
```

### 6.4 Verify UECM deregistration in UDM

```bash
docker logs udm --since=30s | jq 'select(.procedure=="UECMDeregistration")'
# → {"procedure":"UECMDeregistration","msg":"AMF deregistration","supi":"imsi-001010000000001","status":204}
```

### 6.5 Verify context was cleaned in AMF (clean re-registration)

```bash
# After deregistering, restart the UE and verify registration works without conflict
docker start ueransim-ue   # or: make ueransim-only
sleep 5
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "status"
# → mm-state: MM-REGISTERED/NORMAL-SERVICE  (no duplicate context errors)
```

### 6.6 Case: deregistration with UE already in CM-IDLE

```bash
# AMF does not send UEContextReleaseCommand if UE is already CM-IDLE
# (the call is a no-op: CMState != CMConnected)
# To reproduce: wait for gNB to release the radio context (inactivity),
# then execute: deregister switch-off
docker logs amf | jq 'select(.procedure=="Deregistration") | .msg'
# → "UE deregistered"  (no warning from SendUEContextReleaseCommandForUE)
```

### 6.7 Verify wire format with PCAP

```bash
./scripts/pcap-control.sh rotate amf
# ... run deregistration ...
./scripts/pcap-control.sh list amf
# Open .pcap in Wireshark, filter: nas-5gs.message_type == 0x45
# Verify: Deregistration Request (0x45), SwitchOff bit, AccessType
# If non-switch-off: Deregistration Accept (0x46) with SHT=0x02 (integrity+ciphered)
```

> Note: UE re-registers automatically unless you use `disable-5g` or `switch-off`.

---

## 7. Service Request — idle↔connected cycle — TS 23.502 §4.2.3

### 7.1 Force transition to CM-IDLE (AN Release)

```bash
# Connect to gNB's nr-cli and force radio context release
docker exec ueransim-gnb nr-cli UERANSIM-gnb-001-01-1 -e "ue-release imsi-001010000000001"
# Or wait for inactivity timer to expire (~20s in default config)
sleep 5
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "status"
# → cm-state: CM-IDLE
```

### 7.2 Trigger Service Request (UE generates uplink traffic from CM-IDLE)

```bash
# Attempt ping: UE detects CM-IDLE state, sends Service Request and returns to CM-CONNECTED
docker exec ueransim-ue ping -I uesimtun0 172.30.3.100 -c 3
# → First packet may be lost (SR latency), rest should arrive
```

### 7.3 Verify in AMF logs

```bash
docker logs amf --since=30s | jq 'select(.procedure=="ServiceRequest")'
```

Expected result:
```json
{"procedure":"ServiceRequest","msg":"Service Request — returning CM-IDLE UE","tmsi":"..."}
{"procedure":"ServiceRequest","msg":"Service Request received","service_type":1}
{"procedure":"ServiceRequest","msg":"sending InitialContextSetupRequest (Service Request)"}
{"procedure":"ServiceRequest","msg":"Service Request accepted — UE back to CM-CONNECTED","result":"OK"}
```

### 7.4 Verify CM state after Service Request

```bash
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "status"
# → cm-state: CM-CONNECTED
```

### 7.5 Verify PDU session user plane is re-activated (N2SM in InitialContextSetup)

```bash
sleep 3
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-list"
# → PDU Session1: PS-ACTIVE

# Verify data plane works again
docker exec ueransim-ue ping -I uesimtun0 172.30.6.1 -c 4
# → 0% packet loss (first packet may be lost to SR latency)

# Verify the spec'd re-activation path (TS 23.502 §4.2.3.2 step 12):
docker logs amf | grep pdu_sessions_cxt_req       # ICS Request carries the session list
docker logs amf | grep "re-activated by gNB"      # ICS Response CxtRes forwarded to SMF
docker logs smf | grep "UP re-activation"         # upCnxState=ACTIVATING transfer rebuilt
docker logs smf | grep "PFCP SessionModification" # FAR updated with the gNB DL tunnel
```

> **Implementation note**: the AMF re-establishes the N2 context via
> InitialContextSetupRequest carrying Service Accept **and** the
> PDUSessionResourceSetupListCxtReq (N2SM info fetched from the SMF with
> `upCnxState=ACTIVATING`) for every PDU session flagged in the SR's Uplink Data
> Status — direct activation of UPF DL forwarding per TS 23.502 §4.2.3.2 step 12.
> See `docs/procedures/service-request.md`. Requires UERANSIM patch 0051 (stock
> v3.2.8 gNB drops initial NAS messages without a Requested NSSAI).

---

## 8. Log monitoring

### Real-time logs — all procedures

```bash
# All core NFs (structured JSON)
make logs

# UE + gNB only
make logs-ueransim

# Registration events only (procedure/result/error)
make logs-reg
```

### Individual NF logs

```bash
docker logs -f amf 2>&1 | jq '.'
docker logs -f smf 2>&1 | jq '.'
docker logs -f upf 2>&1 | jq '.'
docker logs -f nrf 2>&1 | jq '.'
```

### Useful filters

```bash
# Errors only
docker logs amf 2>&1 | jq 'select(.level == "ERROR")'

# Follow a specific procedure
docker logs -f amf 2>&1 | jq 'select(.procedure != null) | {procedure, result, supi, cause}'

# View only PDU Session messages
docker logs smf 2>&1 | jq 'select(.pdu_session_id != null)'

# Count NAS messages by type
docker logs amf 2>&1 | jq -r '.message_type // empty' | sort | uniq -c | sort -rn
```

---

## 9. Observability (with `make up-obs` or `make ueransim`)

| Tool | URL | What to see |
|---|---|---|
| Grafana | http://localhost:3000 | NF metrics dashboards, alerts |
| Jaeger | http://localhost:16686 | Traces per 3GPP procedure |
| Prometheus | http://localhost:9090 | Raw time series |
| Loki | http://localhost:3100 | Logs (via Grafana, not directly) |

### Search for a trace in Jaeger

1. Open http://localhost:16686
2. Service → `AMF` (or `SMF`, `NRF`, ...)
3. Operation → `InitialRegistration` / `PduSessionEstablishment`
4. Click "Find Traces"

---

## 10. PCAP — traffic capture

```bash
# Status of PCAP sidecars
./scripts/pcap-control.sh status

# List captured files by NF
./scripts/pcap-control.sh list amf
./scripts/pcap-control.sh list nrf

# Pause/resume capture
./scripts/pcap-control.sh pause amf
./scripts/pcap-control.sh resume amf

# Force rotation (new file)
./scripts/pcap-control.sh rotate amf
```

See `docs/pcap-diagnostics.md` for importing TLS keys into Wireshark.

---

## 11. Quick rebuild of a single NF

```bash
# Rebuild only AMF and restart container
make -C nf/amf docker && docker compose up -d amf

# Rebuild SMF
make -C nf/smf docker && docker compose up -d smf

# Rebuild UPF (privileged, needs --privileged in docker)
make -C nf/upf docker && docker compose up -d upf

# Rebuild only UERANSIM (without touching core)
make ueransim-build-only && make ueransim-only
```

---

## 12. Complete validation sequence (golden path)

Run in order to validate the full e2e flow from scratch:

```bash
# 1. Start everything
make ueransim

# 2. Wait ~5 seconds and verify state
sleep 5
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "status"
# → mm-state: MM-REGISTERED/NORMAL-SERVICE

# 3. Verify PDU session automatically established
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-list"
# → PDU Session1: PS-ACTIVE, address: 10.60.0.X

# 4. Verify data plane (N3 → UPF → N6)
docker exec ueransim-ue ping -I uesimtun0 172.30.3.100 -c 4
# → 0% packet loss

docker exec ueransim-ue ping -I uesimtun0 8.8.8.8 -c 4
# → 0% packet loss

# 5. PDU Session Release (verifies UE doesn't crash)
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-release 1"
sleep 2
docker logs ueransim-ue 2>&1 | grep -E "Release|release" | tail -5
# → "PDU Session Release Command received"
# → "Performing local release of PDU session[1]"
# → MUST NOT show: "Bad constructed NAS message" or "std::runtime_error"

# 6. Verify automatic session reestablishment
sleep 3
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-list"
# → New PDU Session active (PSI may change)

# 7. Deregistration (UE-initiated, non-switch-off)
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "deregister normal"
sleep 3
docker logs amf --since=10s | jq 'select(.procedure=="Deregistration") | {msg,switch_off,result}'
# → {"msg":"Deregistration Request received","switch_off":false}
# → {"msg":"sending NAS message","message_type":"46"}
# → {"msg":"UE deregistered","result":"OK"}
docker logs udm --since=10s | jq 'select(.procedure=="UECMDeregistration") | .msg'
# → "AMF deregistration"
```

---

## 13. Quick troubleshooting

| Symptom | First action |
|---|---|
| UE does not register (`MM-DEREGISTERED`) | `docker logs amf \| tail -20` — search for `REJECT` or `ERROR` |
| PDU session not established | `docker logs smf \| tail -30` — verify IP allocation |
| Ping fails from uesimtun0 | `docker logs upf \| tail -20` — verify PFCP session and GTP-U |
| UE crashes with `runtime_error` | Read `docs/validation-commands.md §11` — verify NAS IE format |
| UERANSIM cannot connect to AMF | `docker exec ueransim-gnb nr-cli UERANSIM-gnb... -e "status"` |
| `make ueransim` fails in docker build | `docker system prune -f` and retry |
| UDR has no subscribers after changing UE_COUNT | Use `make ueransim` (not `ueransim-only`) to reseed |

### Additional diagnostic commands

```bash
# View UPF network interface status
docker exec upf ip link show
docker exec upf ip route show

# View active PFCP sessions in UPF
docker logs upf 2>&1 | grep -i "pfcp\|session" | tail -20

# View NGAP signaling in AMF
docker logs amf 2>&1 | jq 'select(.interface == "N2")' | tail -20

# View all NFs registered in NRF
curl -sk https://localhost:8443/nnrf-nfm/v1/nf-instances | jq '[.[] | {nfType, nfStatus, ipv4Addresses}]' 2>/dev/null || \
docker exec amf curl -sk https://nrf:8443/nnrf-nfm/v1/nf-instances 2>/dev/null | head -5

# Verify UPF has iptables MASQUERADE configured
docker exec upf iptables -t nat -L POSTROUTING -n -v
```

---

## Appendix — Docker network map & IP addressing

Map of addresses in the `docker-compose` deployment. Intended for diagnosing
UE connectivity (TUN interface `uesimtunN`) and NF connectivity.

> NFs **do not** have static IPs: Docker assigns them dynamically within each
> subnet. To reach them, use the **container name** (Docker internal DNS). The only
> fixed IPs are `upf_n3_addr` and the UE pools.

### A.1 Docker Networks

| Network   | Subnet           | 3GPP Interface | Who Uses It                         |
|-----------|------------------|----------------|-------------------------------------|
| `sbi-net` | `172.30.0.0/24`  | SBA (HTTP/2)   | All control plane NFs               |
| `n2-net`  | `172.30.1.0/24`  | N2 (NGAP)      | AMF ↔ gNB ↔ UE                      |
| `n4-net`  | `172.30.2.0/24`  | N4 (PFCP)      | SMF ↔ UPF                           |
| `n3-net`  | `172.30.3.0/24`  | N3 (GTP-U)     | gNB ↔ UPF                           |
| `n6-net`  | `172.30.6.0/24`  | N6 (DN)        | UPF ↔ data network                  |
| `obs-net` | dynamic          | —              | Loki, Prometheus, Grafana, Jaeger   |

### A.2 Known Fixed Addresses

| Element                 | Address          | Notes                                  |
|-------------------------|------------------|-----------------------------------------|
| UPF — N3 (GTP-U)        | `172.30.3.100`   | Static (`upf_n3_addr` / `upf n3.ip`)   |
| UPF — N3 GTP-U port     | `:2152/udp`      | GTP-U tunnel                           |
| UPF — N4 PFCP port      | `:8805/udp`      | PFCP sessions from SMF                 |
| AMF — N2 NGAP/SCTP      | `amf:38412`      | gNB connects here                      |

### A.3 Control Plane NFs (Resolve by Name)

Within Docker network, use the container name. From the host, use
`localhost` with the published port.

| NF   | Container / Hostname  | SBI Port | Metrics Port | Published on Host |
|------|------------------------|----------|--------------|-------------------|
| NRF  | `nrf` / `nrf.5gc.local`   | 8000     | 9100         | `localhost:8000`  |
| AMF  | `amf` / `amf.5gc.local`   | 8001     | 9101         | `localhost:8001`  |
| AUSF | `ausf`                    | 8002     | 9102         | —                 |
| UDM  | `udm`                     | 8003     | 9103         | —                 |
| UDR  | `udr`                     | —        | —            | —                 |
| SMF  | `smf` / `smf.5gc.local`   | 8004     | 9105         | `localhost:8004`  |
| PCF  | `pcf` / `pcf.5gc.local`   | 8006     | 9106         | —                 |
| UPF  | `upf` / `upf.5gc.local`   | 8805 (N4)| 9107         | `localhost:8805`  |

AMF — N2: `38412` published on `localhost:38412`.

### A.4 UE IP Pool (TUN Interface)

SMF assigns PDU session addresses from:

```
ue_ip_pool: 10.60.0.0/16
```

The allocator walks the range sequentially and **skips the network address**
(`10.60.0.0`). Thus, on a clean startup:

| UE   | SUPI                      | Assigned TUN IP | Interface    |
|------|-----------------------|-----------:|--------------|
| UE 1 | `imsi-001010000000001`| `10.60.0.1`     | `uesimtun0`  |
| UE 2 | `imsi-001010000000002`| `10.60.0.2`     | `uesimtun1`  |
| UE 3 | `imsi-001010000000003`| `10.60.0.3`     | `uesimtun2`  |
| UE N | `imsi-0010100000000NN`| `10.60.0.N`     | `uesimtunN-1`|

> IPs are assigned in session establishment order; if UEs register in a different
> order the correspondence may vary. Always confirm with
> `nr-cli imsi-... -e "ps-list"` or by checking SMF logs (`allocated_ip`).

### A.5 Ping Recipes

Verify the actual IP assigned to a UE:
```bash
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-list"
docker logs smf | jq -r 'select(.allocated_ip) | "\(.supi) -> \(.allocated_ip)"'
```

Ping from a UE via its TUN (user plane, N3→UPF→N6):
```bash
# UE 1 uses uesimtun0
docker exec ueransim-ue ping -I uesimtun0 -c 4 8.8.8.8

# UE 2 uses uesimtun1
docker exec ueransim-ue ping -I uesimtun1 -c 4 8.8.8.8
```

Ping between two UEs (UE↔UE via user plane):
```bash
docker exec ueransim-ue ping -I uesimtun0 -c 4 10.60.0.2
```

Check N3 to UPF (control/transport, NOT user plane):
```bash
docker exec ueransim-gnb ping -c 4 172.30.3.100
```

SBA connectivity between NFs (by name):
```bash
docker exec amf ping -c 2 nrf
docker exec smf ping -c 2 upf
```

### A.6 Troubleshooting Notes

- If UE ping fails but PDU session is `ACTIVE`, the problem is usually in
  UPF's user plane (GTP-U / N6 forwarding), which in dev is a stub with minimal
  logging.
- `ping -I uesimtunN` is mandatory: without `-I` the packet exits via the container's
  default route, not the PDU session.
- The IPs `172.30.x.x` change if you edit the subnets in `docker-compose.yml`.
- List actual container IPs at any time:
  ```bash
  docker network inspect 5gc-rel17_n3-net | jq -r '.[].Containers[] | "\(.Name) \(.IPv4Address)"'
  ```

---

## 14. Multi-slice suite (T0–T9) and feature quick reference

### Multi-slice validation suite (T0–T9)

```bash
make test-slices   # or: ./scripts/test-slices.sh
```

| Test | What it validates |
|------|------------|
| T0 | `multi-slice` profile containers are running |
| T1 | NRF — SMF announces 4 SNSSAIs |
| T2 | NSSF — NSSelection returns correct slices |
| T3 | UDR — each SUPI has correct NSSAI profile |
| T4 | 4 UEs reach `MM-REGISTERED` (timeout 45 s) |
| T5 | AMF — correct `AllowedNSSAI`; no spurious rejections |
| T6 | PDU sessions established; SMF logs per IMSI |
| T7 | `uesimtun0` active + ping from each UE |
| T8 | Unauthorized UE for gold → `NSSAI_NOT_ALLOWED` |
| T9 | Prometheus metrics accessible on all containers |

### Feature validation quick reference

| Feature | Command / check |
|---------|-----------------|
| PCF SM policy create | `docker logs pcf \| grep SmPolicyCreate` on `ps-establish` |
| PCF SM policy delete | `docker logs pcf \| grep SmPolicyDelete` on `ps-release` |
| NW-initiated deregistration | `curl -X DELETE http://localhost:9002/amf/v1/ue-contexts/<supi>` → `MM-DEREGISTERED` |
| NW-initiated PDU release | `curl -X DELETE http://localhost:9002/amf/v1/ue-contexts/<supi>/pdu-sessions/1` |
| Xn Handover | `make handover-test` → `docker logs amf \| grep PathSwitchRequest` |
| N2 Handover | `make handover-n2-test` → `docker logs amf \| grep HandoverCommand` |
| NRF NFStatusSubscribe/Notify | `docker stop smf` → `docker logs amf \| grep "NF status notification"` |
| NRF DNN filter | `curl ".../nf-instances?...&dnn=internet"` returns SMF; `dnn=voip` returns empty |
| SUCI Profile A | `make ueransim-profile-a` → registration succeeds (`docker logs udm \| grep "SUCI Profile A"`) |
| URSP policy delivery | `make validate-ursp`; `docker logs amf \| grep "UE policy container sent"` |
| PDU session QoS | `docker logs smf \| grep qos_source` (PCF_OVERRIDE / UDM_SUBSCRIPTION / OPERATOR_DEFAULT) |
| NW-initiated QoS mod | `POST .../sessions/1/qos` → `docker logs amf \| grep "QoS Modification Command"` |
| NW-triggered PDU session | portal `/qos?tab=nw-session` (NW-Triggered panel), or `POST /api/v1/qos/nw-sessions` |
| DNN subnet isolation | `docker logs upf \| grep upfgtp0` (internet) / `upfgtp1` (ims) |
| NRF BDD (in-process) | `cd nf/nrf && make test-functional` — 3/3 passing |
| AMF BDD (E2E) | `make ueransim && cd nf/amf && E2E_TEST=1 make test-functional` |

Full recipes for each row are in §15 below; newer features (IPv6, PWS, location, …)
are in the recipes of §15 and in `docs/procedures/`.

---

## 15. Detailed per-feature recipes

Quick-reference for validating each recently implemented feature. Run `make up-obs` first unless stated otherwise.

### PCF SM Policy Lifecycle (TS 29.512 §5.2.2)
```bash
make ueransim
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish default internet"
docker logs pcf | grep SmPolicyCreate    # should appear on session establishment
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-release 1"
docker logs pcf | grep SmPolicyDelete    # should appear on session release
```

### NW-Initiated Deregistration (TS 23.502 §4.2.2.3.3)
```bash
make ueransim
# Force deregistration via management API (port 9002):
SUPI=imsi-001010000000001
curl -X DELETE http://localhost:9002/amf/v1/ue-contexts/$SUPI
# Or use the portal at http://localhost:8080/ueransim → Force Deregister
docker exec ueransim-ue nr-cli --dump    # UE should show MM-DEREGISTERED
docker logs amf | grep NetworkDeregistration
```

### NW-Initiated PDU Session Release (TS 23.502 §4.3.4.3)
```bash
make ueransim
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish default internet"
SUPI=imsi-001010000000001
curl -X DELETE http://localhost:9002/amf/v1/ue-contexts/$SUPI/pdu-sessions/1
docker logs upf | grep SessionDeletion   # PFCP entry cleaned
docker logs amf | grep PDUSessionRelease
```

### Xn Handover (TS 23.502 §4.9.1.2)
```bash
make handover-test
# PacketRusher executes a scripted Xn handover scenario.
# Expected in AMF logs:
docker logs amf | grep PathSwitchRequest
docker logs amf | grep "spec_ref.*4.9.1.2"
docker logs smf | grep PATH_SWITCH_REQ
# Clean up:
make handover-down
```
PacketRusher config: `config/packetrusher/packetrusher.yaml`. Compose service profile: `handover`.

Portal UI: navigate to **PacketRusher** (`http://localhost:8080/packetrusher`) to start/stop/pause
Xn and N2 scenarios, stream live logs (PacketRusher + AMF + SMF tabs), and watch the auto-detected
mobility-event checklist (UE Registered → PDU Session → HO Triggered → Path Switch → Complete).

### N2 Handover via Portal (TS 23.502 §4.9.1.3)
```bash
# Build image first (only needed once):
make handover-test   # builds packetrusher-local image; then stop if desired
# Use portal PacketRusher page → N2 Handover → Start
# Or CLI:
make handover-n2-test
docker logs amf | grep HandoverRequired
docker logs amf | grep HandoverCommand
docker logs amf | grep HandoverNotify
make handover-n2-down
```

### NRF NFStatusSubscribe/Notify (TS 29.510 §5.2.2.7-9)
```bash
make ueransim
# Kill SMF to trigger NF_DEREGISTERED notification:
docker stop smf
# NRF heartbeat eviction fires after TTL; or trigger deregister manually.
docker logs amf | grep "NF status notification"
docker logs nrf | grep NF_DEREGISTERED
# Restart SMF to confirm NF_REGISTERED notification:
docker start smf
docker logs amf | grep NF_REGISTERED
```

### NRF NFDiscover DNN Filter (TS 29.510 §6.2.3.2.3.1)
```bash
make ueransim
# SMF registers with dnnList=["internet"] on NRF startup.
# Verify DNN filter works:
curl -sk "https://localhost:8443/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF&dnn=internet" | jq '.nfInstances | length'  # expect 1
curl -sk "https://localhost:8443/nnrf-disc/v1/nf-instances?target-nf-type=SMF&requester-nf-type=AMF&dnn=voip"    | jq '.nfInstances | length'  # expect 0
# BDD test (in-process, no stack needed):
cd nf/nrf && make test-functional
```

### SUCI Profile A — X25519 ECIES (TS 33.501 §6.12, Annex C.3)
```bash
# UE config: config/ueransim/ue-profile-a.yaml  (protectionScheme: 1)
# Dev key pair — TS 33.501 Annex C.3 published test vector (not a secret; included for out-of-the-box dev use):
#   private: see nf/udm/config/dev.yaml (hn_private_key_x25519)
#   public:  61cdb319f72eddfbac55c06c3ec38d15828880a259cbc11cc03ca92abb60fb5e

# CLI:
make ueransim-profile-a        # core + obs + gnb + ueransim-ue-profile-a
docker logs ueransim-ue-profile-a   # watch nr-ue registration
docker logs udm | grep "SUCI Profile A"   # deconcealment log
docker logs amf | grep "supi.*imsi"       # resolved SUPI in AMF
make ueransim-profile-a-down   # stop

# Portal (run make ueransim-profile-a or make full once to create containers):
# http://localhost:8080/ueransim → Scenarios → SUCI Profile A → Start
```
Home network private key loaded from `nf/udm/config/dev.yaml` (`hn_private_key_x25519`) or `HN_PRIVATE_KEY_X25519` env var.
Docker-compose profile: `suci-profile-a`. Container: `ueransim-ue-profile-a`. Shares `ueransim-gnb` with standard scenario.

### URSP Policy Delivery (TS 24.526 / TS 29.525)
```bash
make ueransim

# Full end-to-end validation suite (U0–U9):
make validate-ursp

# Codec-only unit tests (no stack needed):
make test-ursp-codec

# Manual checks:
SUPI=imsi-001010000000001
docker logs pcf | grep "policy association"          # N15 at registration
docker logs amf | grep "UE policy container sent"    # DL NAS Transport, payload container type 0x05

# URSP is delivered via the UE policy delivery service (TS 24.501 Annex D):
# a MANAGE UE POLICY COMMAND in a DL NAS Transport (payload container type 0x05).
# NOT the Configuration Update Command, NOT IEI 0x7B. UERANSIM v3.2.8 has no
# URSP support, so it logs "Unhandled payload container type [5]" and does not ACK.

# On-demand push (UE must be CM-CONNECTED):
curl -X POST http://localhost:9002/amf/v1/ue-contexts/$SUPI/push-policies
docker logs amf | grep "ursp_version"                # increments on each send

# Decode the UE Policy Container (human-readable URSP rules):
docker exec amf curl -sk --http2-prior-knowledge \
  -X POST https://pcf:8006/npcf-ue-policy-control/v1/ue-policies \
  -H 'Content-Type: application/json' \
  -d "{\"supi\":\"$SUPI\",\"servingPlmn\":\"00101\"}" | \
  python3 scripts/decode-ursp.py

# Per-subscriber override via UDR API:
curl -X PUT http://localhost:8003/nudr-dr/v2/policy-data/$SUPI/ue-policy-set \
  -H "Content-Type: application/json" \
  -d '{"precedence":10,"rules":[{"precedence":10,"traffic_descriptor":{"dnns":["ims"]},"route_sel_descriptors":[{"precedence":1,"ssc_mode":1,"snssai":{"sst":1,"sd":"000002"},"dnn":"ims","pdu_session_type":1}]}]}'

# Portal: http://localhost:8080/policies
#   → Policy Templates section: 4 slice cards (Internet/Gold/Silver/Bronze)
#     Each card: view JSON rules, edit, Apply to UE button
#   → Apply to UE dialog: pick registered UE, optionally customise rules,
#     see 3GPP spec reference (IEI types, delivery path), click Apply & Push
#   → Per-Subscriber Policies section: list active overrides with Push button

# API: apply a template to a UE via portal:
curl -X POST http://localhost:8080/api/v1/policy-templates/<template-id>/apply \
  -H "Content-Type: application/json" \
  -d "{\"supi\":\"$SUPI\"}"
# Returns: {"status":"pushed"} or {"status":"stored","warning":"..."}
```

### PDU Session QoS Management (TS 23.501 §5.7 / TS 23.502 §4.3.3.2)
```bash
make ueransim
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish default internet"

# 5QI selection at establishment: PCF override > UDM subscription (sm-data) > operator default.
docker logs smf | grep "subscribed default QoS"     # N10 Nudm_SDM sm-data fetch
docker logs smf | grep qos_source                   # PCF_OVERRIDE | UDM_SUBSCRIPTION | OPERATOR_DEFAULT
docker logs upf | grep "qer_id"                     # QER installed (TS 29.244 §7.5.2.5)

# Session inspection (SMF management API — internal, not 3GPP):
curl -sk https://localhost:8004/nsmf-management/v1/sessions | jq

# NW-initiated 5QI modification (full §4.3.3.2 flow: N4 QER → N2 Modify → NAS 0xCB):
curl -sk -X POST https://localhost:8004/nsmf-management/v1/sessions/1/qos \
  -H 'Content-Type: application/json' \
  -d '{"5qi":7,"reason":"upgrade to interactive video"}'
docker logs smf | grep NetworkQoSModification
docker logs upf | grep "QER updated"
docker logs amf | grep "QoS Modification Command"

# Subscriber default QoS from UDM:
curl -sk https://localhost:8003/nudm-sdm/v2/imsi-001010000000001/sm-data | jq

# MCP tools: pdu_session_list, pdu_session_qos_get, pdu_session_qos_set, subscription_qos_get.
# Portal: http://localhost:8080/qos (tab `sessions`) — session table, Modify QoS drawer,
#   subscription inspector; collapsible E2E validation panel is tab `validation` (?tab=validation).

# Unit tests:
go test ./shared/nas/ ./nf/smf/internal/server/ ./nf/upf/internal/pfcp/ ./nf/pcf/internal/server/
```

### NW-Triggered Additional PDU Session (TS 23.503 §6.6.2 / TS 23.502 §4.3.2.2.1)
```bash
make ueransim
# 3GPP has no NW-initiated PDU Session Establishment — the network steers the UE via URSP:
# app detected → PCF DNN-scoped QoS override + URSP rule → AMF UE-policy push (DL NAS 0x05)
# → UE-requested establishment of an ADDITIONAL PSI. UE-side URSP evaluation is simulated
# via nr-cli (UERANSIM v3.2.8 has no URSP). See docs/procedures/nw-triggered-pdu-session.md.

# One-shot trigger (orchestrates the 5 steps and verifies the new PSI):
curl -s -X POST http://localhost:8080/api/v1/qos/nw-sessions \
  -H 'Content-Type: application/json' \
  -d '{"supi":"imsi-001010000000001","app":"cloud-gaming","dnn":"internet",
       "sst":1,"sd":"000001","5qi":3,"ambr_uplink":"30 Mbps","ambr_downlink":"100 Mbps"}' | jq
# Expected: success=true, new pdu_session_id (existing sessions untouched), qos_source=PCF_OVERRIDE.
# NOTE: verify takes ~17-25 s — UERANSIM bars the first nr-cli ps-establish on a UAC
# timing race and retransmits on T3580 (+16 s). This is a UERANSIM quirk, not a core issue.

docker logs pcf | grep "QoS override set"            # DNN-scoped override stored
docker logs amf | grep "UE policy container sent"    # URSP delivery (ursp_version increments)
docker logs smf | grep qos_source                    # new session → PCF_OVERRIDE
curl -s http://localhost:8080/api/v1/qos/sessions | jq   # additional PSI listed

# DNN-scoped PCF override directly (internal API):
docker exec amf wget -qO- --no-check-certificate \
  https://pcf:8006/pcf-internal/v1/subscribers/imsi-001010000000001/sm-policy-override?dnn=internet

# Portal: http://localhost:8080/qos?tab=nw-session → "NW-Triggered PDU Session" panel —
#   UE picker, app presets (cloud-gaming/voice-call/video-stream/ims-signalling → 5QI),
#   DNN + S-NSSAI + AMBR form, live 5-step orchestration checklist.

# Unit tests (DNN-scoped override precedence):
go test ./nf/pcf/internal/server/ -run "TestSmPolicyDNNScopedOverride|TestQoSOverrideAPIDNNScope"
```

### Portal layout check (single-scroll shell)
```bash
cd tools/mgmt-portal/web
grep -rnE 'scrollIntoView|h-screen|100vh' src --include='*.tsx' --include='*.ts' --include='*.css'   # must print nothing
npm run build
```
In the browser console on any portal page (http://localhost:8080), at several viewport sizes:
```js
({doc: document.documentElement.scrollHeight <= innerHeight, scrollers:[...document.querySelectorAll('*')].filter(e=>/(auto|scroll)/.test(getComputedStyle(e).overflowY)&&e.scrollHeight>e.clientHeight+1).map(e=>e.tagName+'.'+String(e.className).slice(0,50))})
// Expected: doc === true and at most one scroller (MAIN.relative ... or one inner fill region).
```

### DNN Subnet Isolation (TS 23.501 §5.6.5)
Each DNN has an isolated UE IP pool and a dedicated N6 Docker network.

| DNN | UE Subnet | TUN | N6 Docker Network |
|---|---|---|---|
| `internet` | `10.60.0.0/24` | `upfgtp0` @ `10.60.0.254/24` | `5gc-n6` (`172.30.6.0/24`) |
| `ims` | `10.61.0.0/24` | `upfgtp1` @ `10.61.0.254/24` | `5gc-n6-ims` (`172.30.7.0/24`) |

**Single source of truth**: `config/operator.yaml` `dnns:` section.
Per-NF YAML (`nf/smf/config/dev.yaml`, `nf/upf/config/dev.yaml`) refines pool/TUN details.

**Adding a new DNN** (e.g., `mms`):
1. Add entry in `config/operator.yaml` under `dnns:` with `ue_ip_pool: "10.62.0.0/24"` and `n6_network: "172.30.8.0/24"`
2. Add entry in `nf/smf/config/dev.yaml` under `dnns:` with matching `ue_ip_pool`
3. Add entry in `nf/upf/config/dev.yaml` under `dnns:` with `tun_name: "upfgtp2"`, `tun_addr: "10.62.0.254/24"`, `gateway_ip: "172.30.8.1"`
4. Add `n6-mms-net` (subnet `172.30.8.0/24`) in `docker-compose.yml` and attach UPF to it
5. `make down && make up` (or `make ueransim`)

```bash
# Verify DNN subnet isolation after make ueransim:
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish default internet"
docker logs smf | grep '"dnn":"internet"'   # pool selected
docker logs upf | grep "upfgtp0"           # TUN used for internet

# IMS session (requires UE config with dnn=ims):
docker logs smf | grep '"dnn":"ims"'        # ims pool
docker logs upf | grep "upfgtp1"           # TUN used for IMS
```

### UE Context Transfer (TS 29.518 §5.3.2)
AMF inbound `namf-comm` SBI server (mTLS + HTTP/2, port 8001) — producer/old-AMF side.
```bash
make ueransim   # register a UE first
# Retrieve the UE context by SUPI (or 5g-guti-<…>); mTLS with any NF dev cert:
curl -sk --cert pki/smf.crt --key pki/smf.key --cacert pki/ca.crt \
  -X POST https://localhost:8001/namf-comm/v1/ue-contexts/imsi-001010000000001/transfer \
  -H 'Content-Type: application/json' -d '{"reason":"MOBI_REG"}' | jq
# Expect 200 + ueContext.mmContextList (NasSecurityMode NIAx/NEAx + kamf) + sessionContextList.
docker logs amf | grep "UE context transferred"
# Errors: unknown UE → 404 CONTEXT_NOT_FOUND; missing reason → 400 MANDATORY_IE_MISSING.
# Unit/functional: go test ./nf/amf/internal/sbi/...  &&  go test -tags=functional ./nf/amf/tests/features/...
```

### CN Paging / Network-Triggered Service Request (TS 23.502 §4.2.3.3)
SMF DL-data trigger → AMF `N1N2MessageTransfer` (mTLS SBI :8001) → NGAP **Paging** of a CM-IDLE UE.
The real UPF N4 PFCP Downlink Data Report is UPF-001 (hard stop); the SMF endpoint simulates it.
```bash
make ueransim
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish IPv4 --dnn internet"

# Paging only fires for a CM-IDLE UE. UERANSIM has no UE-side idle command and
# self-reconnects in ~1-3 s, so force CM-IDLE from the gNB and fire DL data immediately:
GNB=UERANSIM-gnb-1-1-1
UEID=$(docker exec ueransim-gnb nr-cli $GNB --exec "ue-list" | grep -oE 'ue-id: [0-9]+' | grep -oE '[0-9]+' | head -1)
docker exec ueransim-gnb nr-cli $GNB --exec "ue-release $UEID"        # AN Release → CM-IDLE
curl -sk --cert pki/smf.crt --key pki/smf.key --cacert pki/ca.crt \
  -X POST "https://localhost:8004/nsmf-management/v1/sessions/1/dl-data-notification?supi=imsi-001010000000001"
# → {"amfCause":"ATTEMPTING_TO_REACH_UE"}
docker logs amf | grep "NGAP Paging sent"            # gnbs_paged, tmsi, tac (TS 38.413 §9.2.8)
docker logs ueransim-gnb | grep -i "Paging received" # gNB got it over N2

# CM-CONNECTED smoke test (no idle needed) → {"amfCause":"N1_N2_TRANSFER_INITIATED"}, no paging.
# NOTE: UERANSIM v3.2.8 UE does not auto-respond to paging with a Service Request — the
# network side (Paging emit + gNB receive) is what is validated live; the UE-side
# reactivation leg is covered by unit + functional tests.
```

### BDD Functional Tests
```bash
# NRF — 3 scenarios, fully in-process (no running stack needed):
cd nf/nrf && make test-functional

# AMF — 3 scenarios, require E2E_TEST=1 + running UERANSIM stack:
make ueransim
cd nf/amf && E2E_TEST=1 make test-functional
# Without E2E_TEST=1 all scenarios report as pending (expected — exit 0).
cd nf/amf && make test-functional
```
