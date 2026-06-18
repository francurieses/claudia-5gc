# 5GC IP Addresses — Ping Testing Reference

Map of addresses in the `docker-compose` deployment. Intended for diagnosing
UE connectivity (TUN interface `uesimtunN`) and NF connectivity.

> NFs **do not** have static IPs: Docker assigns them dynamically within each
> subnet. To reach them, use the **container name** (Docker internal DNS). The only
> fixed IPs are `upf_n3_addr` and the UE pools.

---

## 1. Docker Networks

| Network   | Subnet           | 3GPP Interface | Who Uses It                         |
|-----------|------------------|----------------|-------------------------------------|
| `sbi-net` | `172.30.0.0/24`  | SBA (HTTP/2)   | All control plane NFs               |
| `n2-net`  | `172.30.1.0/24`  | N2 (NGAP)      | AMF ↔ gNB ↔ UE                      |
| `n4-net`  | `172.30.2.0/24`  | N4 (PFCP)      | SMF ↔ UPF                           |
| `n3-net`  | `172.30.3.0/24`  | N3 (GTP-U)     | gNB ↔ UPF                           |
| `n6-net`  | `172.30.6.0/24`  | N6 (DN)        | UPF ↔ data network                  |
| `obs-net` | dynamic          | —              | Loki, Prometheus, Grafana, Jaeger   |

---

## 2. Known Fixed Addresses

| Element                 | Address          | Notes                                  |
|-------------------------|------------------|-----------------------------------------|
| UPF — N3 (GTP-U)        | `172.30.3.100`   | Static (`upf_n3_addr` / `upf n3.ip`)   |
| UPF — N3 GTP-U port     | `:2152/udp`      | GTP-U tunnel                           |
| UPF — N4 PFCP port      | `:8805/udp`      | PFCP sessions from SMF                 |
| AMF — N2 NGAP/SCTP      | `amf:38412`      | gNB connects here                      |

---

## 3. Control Plane NFs (Resolve by Name)

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

---

## 4. UE IP Pool (TUN Interface)

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

---

## 5. Ping Recipes

### Verify the actual IP assigned to a UE
```bash
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-list"
docker logs smf | jq -r 'select(.allocated_ip) | "\(.supi) -> \(.allocated_ip)"'
```

### Ping from a UE via its TUN (user plane, N3→UPF→N6)
```bash
# UE 1 uses uesimtun0
docker exec ueransim-ue ping -I uesimtun0 -c 4 8.8.8.8

# UE 2 uses uesimtun1
docker exec ueransim-ue ping -I uesimtun1 -c 4 8.8.8.8
```

### Ping between two UEs (UE↔UE via user plane)
```bash
docker exec ueransim-ue ping -I uesimtun0 -c 4 10.60.0.2
```

### Check N3 to UPF (control/transport, NOT user plane)
```bash
docker exec ueransim-gnb ping -c 4 172.30.3.100
```

### SBA connectivity between NFs (by name)
```bash
docker exec amf ping -c 2 nrf
docker exec smf ping -c 2 upf
```

---

## 6. Troubleshooting Notes

- If UE ping fails but PDU session is `ACTIVE`, the problem is usually in
  UPF's user plane (GTP-U / N6 forwarding), which in dev is a stub with minimal
  logging (see status in root `CLAUDE.md`).
- `ping -I uesimtunN` is mandatory: without `-I` the packet exits via the container's
  default route, not the PDU session.
- The IPs `172.30.x.x` change if you edit the subnets in `docker-compose.yml`.
- List actual container IPs at any time:
  ```bash
  docker network inspect 5gc-rel17_n3-net | jq -r '.[].Containers[] | "\(.Name) \(.IPv4Address)"'
  ```
</content>
</invoke>
