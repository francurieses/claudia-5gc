<!-- tier: public -->
# Troubleshooting

## Docker: "permission denied" when `make` builds an image

```
ERROR: permission denied while trying to connect to the Docker daemon socket
```

Your user is not in the `docker` group:

```bash
sudo usermod -aG docker $USER && newgrp docker
```

Then retry without `sudo`. Do **not** run `sudo make` — it breaks the portal's npm build.

## The stack does not come up

- `docker ps` — every NF should be `healthy`. `docker logs <nf>` shows why one is not.
- NFs register with the NRF at start-up; if the NRF is down, start it first (`make up`).
- After `make down` (which removes volumes) the first start re-seeds the database; wait for the UDR to log that subscribers are seeded.
- Certificates missing or expired: `make pki` regenerates the development PKI.

## The UE does not register

1. `docker ps | grep ueransim` — gNB and UE containers running.
2. `docker logs ueransim-gnb` — look for the NG Setup with the AMF.
3. `docker logs amf | grep -i ngap` — the AMF should show the gNB connecting on 38412/sctp.
4. `docker exec ueransim-ue nr-cli imsi-001010000000001 --dump` — expect `MM-REGISTERED/NORMAL-SERVICE`.
5. After changing `UE_COUNT` use `make ueransim` (it reseeds the UDR), not `make ueransim-only`.

## Common messages

| Symptom | Likely cause |
|---|---|
| `NSSAI_NOT_ALLOWED` | the UE asked for a slice it is not subscribed to — check its subscription in Portal → Subscribers |
| PDU session rejected with 5GMM cause #90 | requested S-NSSAI is not in the UE's Allowed NSSAI (by design) |
| `Unhandled payload container type [5]` on the UE | URSP was delivered; stock UERANSIM does not support it (use the image built by this repo) |
| Session works but QoS is the operator default | the slice's DNN does not match the DNN the UE requests |
| Slow downlink TCP from a Mac host | Docker Desktop network proxy; the UPF repairs checksums by default (`n6.l4_checksum_repair`) |

## Capture and inspect traffic

```bash
./scripts/pcap-control.sh rotate amf       # start a fresh capture
# reproduce the problem, wait ~10 s
./scripts/pcap-control.sh list amf
```

Open the newest file in Wireshark. See [`observability.md`](observability.md) for metrics, traces and
logs. Deeper message-level diagnostics are part of the members documentation.

## Still stuck?

Open an issue on the GitHub repository with the NF logs (`docker logs <nf>`) and the output of `docker ps`.
