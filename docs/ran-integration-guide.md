# Real RAN Integration Guide

This guide covers every parameter and network change required to connect a physical or third-party
software gNB to this 5GC implementation.  It is structured as a top-to-bottom checklist: complete
each section in order and you will have a working end-to-end 5G SA system.

---

## 1. Network Topology

The core uses five isolated Docker bridge networks.  In a real deployment, the gNB must reach two
of them (N2 and N3); all other interfaces remain internal.

```
                      ┌──────────────────────────────────────────────────┐
                      │                 5GC Server                        │
                      │                                                    │
  gNB ──── N2 (NGAP) ──► AMF  :38412/TCP  (172.30.1.0/24 in dev)         │
       ──── N3 (GTP-U) ──► UPF  :2152/UDP   (172.30.3.100 in dev)        │
                      │    │                                               │
                      │    └── N6 (TUN upfgtp0) ──► Internet / DN         │
                      │                                                    │
                      │  Internal SBI (172.30.0.0/24): NRF/AUSF/UDM/...  │
                      └──────────────────────────────────────────────────┘
```

**In production the AMF and UPF bind `0.0.0.0` so Docker publishes their ports to the host.  The
gNB must point at the host's external IP.**

---

## 2. PLMN (MCC / MNC)

PLMN must match across the entire system: all NFs, every gNB, and every UE SIM/config.

**Current value: MCC `001`, MNC `01` (test PLMN, TS 23.003 §4.6)**

### Single file to edit

All NFs read PLMN from one shared file:

```
config/operator.yaml
```

```yaml
plmn:
  mcc: "001"   # ← change here only
  mnc: "01"    # ← change here only
```

Every NF container mounts this file at `/etc/5gc/operator.yaml` (see `docker-compose.yml`).
Changing `config/operator.yaml` and restarting the stack is all that is required — no per-NF
config file needs to be touched.

### Subscriber database

When MCC/MNC changes you must also update the seeded subscriber IMSIs.  SUPI format is
`imsi-<MCC><MNC><MSIN>`, e.g. for MCC=310, MNC=410: `imsi-310410000000001`.

The UDR seed code reads the PLMN from the runtime SUPI format; update `UE_COUNT` seeded IMSIs
via the management portal (`http://localhost:8080`) or the UDR API after boot.

---

## 3. AMF Identity (5G-GUTI components)

These three fields identify the AMF globally (TS 23.003 §2.10.1).  They affect the 5G-GUTI
assigned to each UE and appear in NGAP NG Setup.  Change them to match your operator's allocation.

**File:** `nf/amf/config/dev.yaml`

```yaml
amf_region_id: 0x01   # 8-bit  — unique within PLMN
amf_set_id:    0x001  # 10-bit — unique within region
amf_id:        0x01   # 6-bit  — unique within set
```

---

## 4. Tracking Area Code (TAC)

The TAC is broadcast by the gNB and verified by the AMF.  A mismatch causes NG Setup Failure.

**There is no TAC field in the AMF config** — the AMF accepts any TAC that the gNB announces in
the NG Setup Request as long as the PLMN matches.  Set the TAC in your gNB configuration and it
will be stored in the UE context after Initial Registration.

For UERANSIM the field is `tac: 1` in `config/ueransim/gnb.yaml`.  For real gNBs set it in the
gNB O&M/configuration tool.

---

## 5. Network Slices (S-NSSAI)

The four default slices are:

| Slice | SST | SD | Label |
|-------|-----|----|-------|
| internet | 1 | `000001` | eMBB best-effort |
| gold | 1 | `000002` | eMBB premium |
| silver | 2 | `000001` | URLLC |
| bronze | 3 | `000001` | MIoT |

### Single file to edit

All NFs that need the slice list (AMF, SMF, NSSF) read it from the same shared file as PLMN:

```
config/operator.yaml
```

```yaml
snssais:
  - sst: 1
    sd: "000001"   # internet
  - sst: 1
    sd: "000002"   # gold
  - sst: 2
    sd: "000001"   # silver
  - sst: 3
    sd: "000001"   # bronze
```

**One edit propagates to AMF (NG Setup Response), SMF (NRF profile), and NSSF (selection policy).**

The gNB slice list (UERANSIM: `slices[]` in `config/ueransim/gnb.yaml`; real gNB: O&M config)
must be kept in sync manually — it is an external tool that cannot read this file.

URSP rules in `nf/pcf/config/dev.yaml` (`default_ursp.rules[].route_descriptors[].snssai`) also
reference slices — update those manually if you add or remove slices (this is a policy rule, not
the slice list).

---

## 6. N2 Interface — AMF NGAP

The AMF listens for NGAP connections on port **38412**.

**File:** `nf/amf/config/dev.yaml`

```yaml
ngap:
  address: "0.0.0.0:38412"   # binds all interfaces inside the container
```

**docker-compose.yml** publishes this port to the host:
```yaml
ports:
  - "38412:38412"   # host_port:container_port
```

### What to configure on the gNB

| gNB parameter | Value |
|---------------|-------|
| AMF IP address | `<server-host-IP>` (the machine running Docker) |
| AMF NGAP port | `38412` |
| PLMN | match §2 |
| Slices | match §5 |

> **SCTP note**: The current implementation uses TCP with a 4-byte length prefix instead of real
> SCTP (SCTP requires kernel modules and special socket handling).  Most commercial and OSS gNBs
> expect real SCTP on port 38412.  To enable SCTP replace the TCP listener in
> `nf/amf/internal/ngap/server.go` with `github.com/ishidawataru/sctp`.  Until then, UERANSIM with
> `ignoreStreamIds: true` and PacketRusher work because they tolerate TCP.

---

## 7. N3 Interface — UPF GTP-U

GTP-U user-plane traffic flows between the gNB and the UPF on UDP port **2152**.

### Critical parameter: `n3.ip`

**File:** `nf/upf/config/dev.yaml`

```yaml
n3:
  address: "0.0.0.0:2152"   # GTP-U listener
  ip: "172.30.3.100"         # ← THE IP THE gNB MUST REACH
```

The `n3.ip` value is advertised to the gNB inside the N3 address field of the PDU Session Resource
Setup Request (via N2SM Transfer).  **It must be the IP that the gNB can actually route to.**

In the development environment `172.30.3.100` is a Docker bridge address visible only on the host.
For a real gNB you have two options:

**Option A — gNB on the same host (e.g. software gNB in another container or local process)**

Keep `172.30.3.100` and ensure the gNB can reach that Docker bridge network.

**Option B — gNB on a remote machine**

Change `n3.ip` to the host's external NIC IP (or a routable IP on the N3 path):

```yaml
# nf/upf/config/dev.yaml
n3:
  address: "0.0.0.0:2152"
  ip: "203.0.113.10"   # replace with actual N3 interface IP of the server
```

Also update `upf_n3_addr` in SMF so it inserts the correct IP into N2SM transfers:

```yaml
# nf/smf/config/dev.yaml
upf_n3_addr: "203.0.113.10"   # must match upf.n3.ip
```

And update the docker-compose port binding so GTP-U is reachable from outside:

```yaml
# docker-compose.yml — upf service
ports:
  - "2152:2152/udp"   # already there — no change needed if binding 0.0.0.0
```

---

## 8. N4 Interface — SMF ↔ UPF (PFCP)

PFCP runs on UDP port **8805** and is internal between SMF and UPF.  No change is required unless
you move SMF and UPF to separate hosts.

| Parameter | Location | Value |
|-----------|----------|-------|
| UPF N4 bind | `nf/upf/config/dev.yaml` → `n4.address` | `0.0.0.0:8805` |
| SMF peer UPF | `nf/smf/config/dev.yaml` → `peers.upf` | `upf:8805` (Docker DNS) |

If running on separate hosts replace `upf` with the UPF host IP.

---

## 9. N6 Interface — UPF Data Network Routing

The UPF creates a Linux TUN interface (`upfgtp0`) and uses iptables NAT to route UE traffic to
the internet (or a test DN).

**File:** `nf/upf/config/dev.yaml`

```yaml
ue_ip_pool: "10.60.0.0/16"   # IP range allocated to UEs by the SMF

n6:
  tun_name: "upfgtp0"          # TUN interface name (arbitrary)
  tun_addr: "10.60.0.254/16"   # Gateway IP assigned to the TUN
  gateway_ip: "172.30.6.1"     # Next-hop toward the DN (N6 Docker bridge GW)
```

At startup the UPF executes (see `nf/upf/internal/tun/tun.go`):

```bash
ip link set upfgtp0 up
ip addr add 10.60.0.254/16 dev upfgtp0
iptables -P FORWARD ACCEPT
iptables -t nat -A POSTROUTING -s 10.60.0.0/16 ! -o upfgtp0 -j MASQUERADE
```

### What this means for a real deployment

1. **UE IP pool** (`10.60.0.0/16`) must not overlap with any existing subnet on the server.
2. **MASQUERADE** translates UE IPs to the UPF's outbound IP — the DN sees traffic from the UPF,
   not the UE.  This is correct for most scenarios.
3. If you need the DN to see actual UE IPs (e.g., fixed-IP UEs, IMS), remove the MASQUERADE rule
   and add a static route on the DN router: `ip route add 10.60.0.0/16 via <UPF-N6-IP>`.
4. For internet access the host/server must have a default route and NAT to the internet.  The UPF
   container inherits the host's N6 gateway via the `n6-net` Docker bridge.

### SMF UE IP pool

The SMF must use the **same pool** as the UPF:

```yaml
# nf/smf/config/dev.yaml
ue_ip_pool: "10.60.0.0/16"   # must match upf.ue_ip_pool
```

---

## 10. Subscriber Provisioning (UDR / UDM)

### Default test subscriber

| Field | Value |
|-------|-------|
| SUPI | `imsi-001010000000001` |
| K | `465B5CE8B199B49FAA5F0A2EE238A6BC` |
| OPc | `E8ED289DEBA952E4283B54E88E6183CA` |
| AMF | `8000` |
| SQN | `000000000001` |
| Algorithm | Milenage |

The UDR seeds subscribers on startup using the `UE_COUNT` environment variable
(`docker-compose.yml → udr → environment.UE_COUNT`).  Additional IMSIs follow the pattern
`imsi-<MCC><MNC>000000000N` where N increments from 1.

### Adding real subscribers

Use the management portal at `http://<server>:8080` → **Subscribers** → **Add Subscriber**, or
call the UDR API directly:

```bash
curl -X POST http://localhost:8005/nudr-dr/v2/subscription-data/<SUPI>/authentication-data \
  -H "Content-Type: application/json" \
  -d '{
    "supi": "imsi-<MCC><MNC><MSIN>",
    "k": "<K-hex>",
    "opc": "<OPc-hex>",
    "sqn": "000000000001",
    "amf": "8000",
    "auth_management_field": "8000"
  }'
```

### SUCI Profile A (X25519 ECIES, TS 33.501 §6.12)

If the UE uses `protectionScheme: 1` (SUCI Profile A), the UDM must have the home-network private
key:

```yaml
# nf/udm/config/dev.yaml
# This is the TS 33.501 Annex C.3 published test vector — included for out-of-the-box dev use.
# Replace with a freshly generated key for any real deployment.
hn_private_key_x25519: "c80949d0c3e4d73a54f8b49fbee7793c5c1de649d7e26ef8b05e0a1e0c8c12e9"
```

The corresponding public key that goes in the UE/SIM is:
`61cdb319f72eddfbac55c06c3ec38d15828880a259cbc11cc03ca92abb60fb5e`

Generate a fresh key pair for production:
```bash
openssl genpkey -algorithm X25519 | openssl pkey -text -noout
```

---

## 11. Security — NAS Ciphering

**File:** `nf/amf/config/dev.yaml`

```yaml
security:
  null_ciphering: true   # dev only — disables NAS encryption (NEA0)
```

**Set `null_ciphering: false` in production.**  With `true` the AMF negotiates NEA0 with every
UE regardless of UE capability, sending NAS in plain text.  This is useful for Wireshark capture
during development but violates TS 33.501 §6.7.2 in production.

When `null_ciphering: false` the AMF negotiates NEA2 (AES-CTR) + NIA2 (AES-CMAC) by default.
Ensure the real UE/SIM supports 128-NIA2 and 128-NEA2.

---

## 12. PKI / TLS Certificates

All SBI interfaces (NRF, AUSF, AMF, UDM, UDR, SMF, PCF, NSSF) use mutual TLS.

### Development certificates

Located in `pki/`.  Generated by `make pki` (calls `scripts/gen-pki.sh`).  The CA is
`pki/ca.crt`.  Each NF has `pki/<nf>.crt` and `pki/<nf>.key`.

Certificate paths in configs:
```yaml
# example: nf/amf/config/dev.yaml
sbi:
  cert_file: "/etc/5gc/pki/amf.crt"
  key_file:  "/etc/5gc/pki/amf.key"
  ca_file:   "/etc/5gc/pki/ca.crt"
```

### Production

Replace dev certificates with operator-signed ones (PLMN CA per TS 33.501 §13).  Mount them at
the same paths or change `cert_file`/`key_file`/`ca_file` in each NF config.

> The gNB does **not** need TLS certificates — N2 (NGAP) is not TLS-protected in this
> implementation.  N3 (GTP-U) has no authentication either (standard behaviour).

---

## 13. Docker-Compose — Exposing Ports to the Host

The relevant ports already have host bindings in `docker-compose.yml`.  Verify the host firewall
allows them:

| Port | Protocol | NF | Interface | Must be reachable by |
|------|----------|----|-----------|----------------------|
| 38412 | TCP* | AMF | N2 NGAP | gNB |
| 2152 | UDP | UPF | N3 GTP-U | gNB |
| 8805 | UDP | UPF | N4 PFCP | SMF (internal) |
| 8080 | TCP | Portal | Management UI | operator browser |
| 8000–8007 | TCP | NFs | SBI HTTPS | internal only |
| 9100–9109 | TCP | NFs | Prometheus | internal / monitoring |

\* TCP stub, not real SCTP — see §6.

```bash
# Open N2 and N3 on the host firewall (example — adjust for your distro/cloud):
sudo iptables -A INPUT -p tcp --dport 38412 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 2152  -j ACCEPT
```

---

## 14. UPF Routing — Host-Level Requirements

The UPF runs inside Docker with `cap_add: [NET_ADMIN]` and `net.ipv4.ip_forward: 1`.  For the
N6 traffic to actually reach the internet from the host:

```bash
# On the host (not inside Docker):
# 1. Enable IP forwarding if not already on:
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# 2. If you want UPF container to reach the internet through the host NIC,
#    the n6-net Docker bridge (172.30.6.0/24) needs a MASQUERADE rule on the host:
sudo iptables -t nat -A POSTROUTING -s 172.30.6.0/24 -j MASQUERADE

# 3. Verify the n6-net bridge gateway is routable from within the UPF container:
docker exec upf ip route show   # should show a default via 172.30.6.1
```

The UPF's internal iptables MASQUERADE (set up by `tun.Setup`) handles `10.60.0.0/16 → N6`, and
the host-level MASQUERADE handles `172.30.6.0/24 → internet`.

---

## 15. Full Parameter Change Checklist

Use this as a pre-flight list before bringing the core up against a real gNB.

### PLMN change

- [ ] `config/operator.yaml` — `plmn.mcc`, `plmn.mnc` **(one file, all NFs)**
- [ ] UDR subscriber seed — provision new SUPIs with updated IMSI format
- [ ] `config/ueransim/gnb.yaml` and `config/ueransim/ue*.yaml` — `mcc`, `mnc`
- [ ] `config/packetrusher/packetrusher.yaml` — `mcc`, `mnc`
- [ ] Real gNB O&M config — MCC/MNC fields

### Slices change

- [ ] `config/operator.yaml` — `snssais[]` **(one file → AMF + SMF + NSSF)**
- [ ] `nf/pcf/config/dev.yaml` — `default_ursp.rules[].route_descriptors[].snssai` (policy rule, not slice list)
- [ ] `config/ueransim/gnb.yaml` — `slices[]`
- [ ] Real gNB O&M config — slice list

### N2 (AMF NGAP) change

- [ ] gNB AMF IP → set to server host IP
- [ ] gNB AMF port → `38412`
- [ ] Host firewall allows TCP 38412 inbound
- [ ] (optional) Replace TCP stub with real SCTP in `nf/amf/internal/ngap/server.go`

### N3 (UPF GTP-U) change

- [ ] `nf/upf/config/dev.yaml` — `n3.ip` → routable IP of the UPF host
- [ ] `nf/smf/config/dev.yaml` — `upf_n3_addr` → same IP as `n3.ip`
- [ ] Host firewall allows UDP 2152 inbound
- [ ] gNB N3 IP configured to reach UPF N3 address

### UPF data-plane change

- [ ] `nf/upf/config/dev.yaml` — `ue_ip_pool` (no overlap with existing subnets)
- [ ] `nf/smf/config/dev.yaml` — `ue_ip_pool` (identical to UPF value)
- [ ] `nf/upf/config/dev.yaml` — `n6.tun_addr` (gateway within pool, e.g. `10.60.0.254/16`)
- [ ] Host-level iptables MASQUERADE on n6-net bridge (see §14)
- [ ] IP forwarding enabled on host

### Subscriber provisioning

- [ ] Real subscriber K, OPc, MSIN loaded into UDR
- [ ] SUPI format: `imsi-<MCC><MNC><MSIN>`
- [ ] If SUCI Profile A: `nf/udm/config/dev.yaml` — `hn_private_key_x25519`

### Security

- [ ] `nf/amf/config/dev.yaml` — `security.null_ciphering: false` for production
- [ ] TLS certificates replaced with operator-signed certs (optional for lab, required for field)

### Rebuild and restart

After any config change:
```bash
make down
make up      # or make up-obs for observability stack
```

After changing Go source (SCTP, seed data, etc.):
```bash
make build   # rebuilds all NF images
make up
```

---

## 16. Connectivity Verification

Once the gNB is connected, verify each interface in sequence:

```bash
# 1. N2 — NG Setup completed (AMF accepted the gNB)
docker logs amf | grep "NG Setup"

# 2. Initial registration — UE registered and got 5G-GUTI
docker logs amf | grep "RegistrationAccept"

# 3. Authentication — 5G-AKA challenge/response exchanged
docker logs ausf | grep "AuthenticationConfirmation"

# 4. PDU Session — UE has an IP address
docker logs smf | grep "SessionEstablishment"
docker logs smf | grep "ue_ip"

# 5. GTP-U — user-plane tunnel up
docker logs upf | grep "SessionEstablishment"

# 6. Data connectivity — ping from UE
# (from UE, after PDU session established)
ping -I <ue-pdu-iface> 8.8.8.8

# 7. Verify UPF receives GTP-U traffic
docker exec upf tcpdump -i eth1 -n 'udp port 2152' -c 10
```

---

## 17. Quick Reference: All Config File Locations

```
config/operator.yaml        ← PLMN (MCC/MNC) + full slice list — THE ONE FILE TO EDIT
                              All NF containers mount it at /etc/5gc/operator.yaml

nf/amf/config/dev.yaml      AMF identity (region/set/id), N2 port, timers, peers, security
nf/smf/config/dev.yaml      SBI port, ue_ip_pool, upf_n3_addr, peers
nf/upf/config/dev.yaml      n3.address, n3.ip, n4.address, ue_ip_pool, n6.*
nf/nrf/config/dev.yaml      SBI port, heartbeat_timeout_sec
nf/ausf/config/dev.yaml     SBI port, peers (nrf, udm)
nf/udm/config/dev.yaml      SBI port, hn_private_key_x25519, peers (nrf, udr)
nf/udr/config/dev.yaml      SBI port
nf/nssf/config/dev.yaml     SBI port, peers (nrf)
nf/pcf/config/dev.yaml      SBI port, default QoS policy, default_ursp rules (policy, not slice list)
docker-compose.yml           Docker networks (subnets), fixed IPs (UPF 172.30.3.100), port bindings
pki/                         TLS certificates — regenerate with `make pki`
```
