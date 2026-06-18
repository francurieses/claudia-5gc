# CLAUDE.md — NSSF (Network Slice Selection Function)

> Read the root `CLAUDE.md` first for global conventions.

## 1. Function

NSSF selects the network slices that can be used by a UE during the registration
process. Receives the requested NSSAI and returns the authorized AllowedNSSAI,
preventing AMF from having to contain slice selection logic.

**Primary specifications:**
- TS 23.501 §5.15.2 — Network slice selection
- TS 23.502 §4.2.9 — Network Slice Selection during Registration
- **TS 29.531** — Nnssf_NSSelection service (SBI)

## 2. Reference Points

| Interface | Peer | Protocol | Spec |
|---|---|---|---|
| N22 | AMF | Nnssf_NSSelection/HTTPS | TS 29.531 |

## 3. SBI Endpoints

| Method | Path | Operation | Spec |
|---|---|---|---|
| GET | `/nnssf-nsselection/v2/network-slice-information` | NSSelection_Get | TS 29.531 §5.2.2.2.3.1 |
| GET | `/healthz` | Liveness probe | — |
| GET | `/metrics` | Prometheus | — |

## 4. NSSelection_Get Endpoint Parameters

| Query param | Type | Mandatory | Description |
|---|---|---|---|
| `nf-type` | string | Yes | Requesting NF type (e.g., `AMF`) |
| `nf-id` | string | Yes | Requesting NF instance ID |
| `slice-info-request-for-registration.requestedNssai` | JSON array | No | Requested S-NSSAIs (`[{"sst":1,"sd":"000001"}]`) |
| `requested-nssai.sst` / `requested-nssai.sd` | int/string | No | Alternative form (single S-NSSAI) |

If `requestedNssai` is empty, returns all configured slices.

## 5. Slice Policy (MVP)

Policy is static: loaded from `config.yaml` in `allowed_slices`.
The `slice.Store` computes the intersection between the requested NSSAI and the
allowed slices. Empty SD in `requested` is a wildcard matching any SD with the same SST. Ref: TS 23.501 §5.15.2.

Future improvement: query UDR for per-subscriber dynamic policy.

## 6. Internal Architecture

```
cmd/nssf/
  main.go             Bootstrap + NRF registration + graceful shutdown
internal/
  config/             Config loader (YAML)
  server/             HTTP/2 SBI server + NSSelection handler
  slice/              Slice policy store (static from config)
config/dev.yaml       Config for docker-compose dev
```

## 7. Integration with AMF

AMF can delegate slice selection to NSSF if the address is configured:

```yaml
# nf/amf/config/dev.yaml
peers:
  nssf: "nssf:8007"
```

AMF intersects NSSF's result with UDM subscription to guarantee that no unsubscribed
slice is ever assigned. If NSSF fails, AMF performs local selection. Ref: TS 23.502 §4.2.9.

## 8. Commands

```bash
make -C nf/nssf build
make -C nf/nssf test
make -C nf/nssf docker

# Unit tests
go test ./nf/nssf/... -v
```

## 9. Debugging

```bash
# View NSSF logs
docker logs -f nssf | jq '.procedure, .nf_type, .requested_count, .allowed_count'

# Call endpoint directly
curl -sk "https://localhost:8007/nnssf-nsselection/v2/network-slice-information?nf-type=AMF&nf-id=amf-001" | jq .

# PCAP of N22 traffic (SBI)
./scripts/pcap-control.sh list nssf
```
