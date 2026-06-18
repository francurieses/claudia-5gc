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

### 7.5 Verify PDU session is reestablished (UERANSIM auto-reestablish)

```bash
sleep 3
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-list"
# → PDU Session1: PS-ACTIVE

# Verify data plane works again
docker exec ueransim-ue ping -I uesimtun0 172.30.3.100 -c 4
# → 0% packet loss
```

> **Implementation note**: AMF re-establishes the N2 context via InitialContextSetupRequest
> with Service Accept. PDU sessions are restored by UERANSIM via normal UL NAS Transport.
> Direct activation of UPF DL forwarding (step 6 of TS 23.502 §4.2.3) requires
> including N2SM info in InitialContextSetupRequest — pending in next iterations.

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
