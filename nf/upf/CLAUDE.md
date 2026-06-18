# CLAUDE.md — UPF (User Plane Function)

> Read the root `CLAUDE.md` first for global conventions.

## 1. Function

The UPF is the user traffic router. It receives GTP-U packets from gNB on N3, decapsulates them, routes them toward the network (N6), and encapsulates return traffic in GTP-U.

**Primary specifications:**
- TS 23.501 §6.2.3 — UPF architecture
- **TS 29.244** — PFCP (N4 interface, control plane)
- **TS 29.281** — GTP-U (N3/N6 interfaces, user plane)

## 2. Reference Points

| Interface | Peer | Protocol | Spec |
|---|---|---|---|
| N4 | SMF | PFCP/UDP port 8805 | TS 29.244 |
| N3 | gNB | GTP-U/UDP port 2152 | TS 29.281 |
| N6 | PDN/Internet | IP forwarding | (via TUN) |

## 3. Implementation Status

| Component | Status |
|---|---|
| PFCP Association Setup | ✅ |
| PFCP Session Establishment | ✅ |
| PFCP Session Modification (DL tunnel) | ✅ |
| GTP-U UDP listener (port 2152) | ✅ |
| GTP-U decapsulation + ext. header skip | ✅ |
| ICMP echo responder (inline, no TUN) | ✅ |
| GTP-U encapsulation + DL reply | ✅ |
| TUN interface + IP forwarding (N6) | ✅ |
| NAT masquerade (N6 outbound) | ✅ |

## 4. User Plane Architecture

```
gNB (N3)
  |
  | GTP-U packets (with PDU Session Container ext. header, TS 38.415)
  v
UPF GTP-U server (port 2152)
  |
  | Skip extension headers (walk chain until nextExtHdrType == 0)
  | Decapsulate inner IP packet
  v
For dst == UPF N3 IP (172.30.3.100):
  ICMP echo → build reply inline → re-encapsulate in GTP-U → send to gNB
For other dst:
  Forward to N6 (not implemented yet — needs TUN + routing)
```

**Critical note — PDU Session Container (TS 38.415)**:
UERANSIM and real 5G NR gNBs send GTP-U with flags `E=1, S=1` and a PDU Session
Container extension header (type 0x85). The real header is >12 bytes:
- Mandatory (8 bytes): flags + type + length(2) + TEID(4)
- Extended optional fields (4 bytes): seqNum(2) + nPDU(1) + nextExtHdrType(1)
- PDU Session Container (4+ bytes): len(1) + data + nextExtHdrType(1)

If parsed with fixed hdrLen=12, the first byte of inner IP is actually the
extension length byte (e.g., 0x01) → IPv4 version=0 ≠ 4 → silent drop.
The `handlePacket` function walks the extension chain correctly.

## 5. PFCP — Session Table

The UPF maintains a `SessionTable` shared between the PFCP server and GTP-U server,
indexed by UP SEID and UL TEID.

```
Association Setup Request → Association Setup Response
Session Establishment Request → Session Establishment Response
  (stores: cpSEID, ulTEID, ueIP)
Session Modification Request → Session Modification Response
  (stores: dlTEID, gnbIP — learned from N2SM Transfer via SMF)
```

The table is queried in GTP-U: `sessions.GetByULTEID(teid)` returns the session with
dlTEID and gnbIP to encapsulate the response.

## 6. Configuration

```yaml
nf_instance_id: "..."
# plmn and dnns.ue_ip_pool come from config/operator.yaml (single source of truth)
n3:
  address: "0.0.0.0:2152"
  ip: "172.30.3.100"  # Announced to gNB for GTP-U
n4:
  address: "0.0.0.0:8805"  # PFCP
metrics:
  address: "0.0.0.0:9107"

# Per-DNN N6 TUN configuration (TS 23.501 §5.6.5, TS 29.244 §6.3.3.14)
# Each DNN gets an isolated TUN interface and subnet.
# To add a new DNN: add entry here + operator.yaml + smf/config + docker-compose n6 network.
dnns:
  - name: internet
    ue_ip_pool: "10.60.0.0/24"
    tun_name: "upfgtp0"
    tun_addr: "10.60.0.254/24"
    gateway_ip: "172.30.6.1"    # Docker bridge for n6-net
  - name: ims
    ue_ip_pool: "10.61.0.0/24"
    tun_name: "upfgtp1"
    tun_addr: "10.61.0.254/24"
    gateway_ip: "172.30.7.1"    # Docker bridge for n6-ims-net
```

**Subnet routing**: The GTP-U server selects the correct TUN by matching the UE source IP
against each DNN's subnet CIDR. No DNN name lookup is needed in the fast path.

## 7. Future Extensions (Full Data Plane)

1. Maintain session table with UE IP → gNB tunnel mapping (TEID, N3 IP)
2. Create TUN interface `upf0` and configure route 10.60.0.0/16
3. Launch GTP-U goroutine to decapsulate inbound packets → TUN
4. Launch TUN goroutine to encapsulate TUN packets → GTP-U outbound
5. Enable IP forwarding, NAT outbound on N6

## 8. Debugging

```bash
docker logs -f upf | jq '.procedure, .interface'
```

To see GTP-U traffic:

```bash
docker exec upf tcpdump -i eth1 -n 'udp port 2152'  # N3 interface
```

## 9. Commands

```bash
make -C nf/upf build
make -C nf/upf test
make -C nf/upf docker
make -C nf/upf run
```

## 10. Security Notes

- UPF requires `cap_add: [NET_ADMIN]` in docker-compose to create TUN and manipulate routes
- In production: SELinux/AppArmor policies, disable CAP_SYS_ADMIN after initial setup
- GTP-U has no authentication: origin verification at SMF (gNB learning in Initial UE Message)
