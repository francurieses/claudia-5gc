# Getting Started — ClaudIA 5GC

Long-form setup and operations guide. The [README](../README.md) has the 6-command quickstart;
this page holds everything else: prerequisites, troubleshooting, the Make reference, scenario
toggles and UERANSIM usage. `make help` is the canonical list of Make targets.

## Prerequisites

The following tools must be installed and accessible to your user (not just root) before running any `make` target.

| Tool | Minimum version | Notes |
|------|----------------|-------|
| **Docker Engine** | 24.x | Must be usable without `sudo` — see [Docker permissions](#docker-permission-denied-make-fails-on-docker-build) below |
| **Docker Compose** | v2 (plugin) | Comes bundled with Docker Desktop / Engine ≥ 24 |
| **Make** | GNU Make 4.x | `sudo apt install make` on Debian/Ubuntu |
| **npm** | 18+ (Node LTS) | Only needed for the portal build. **Cannot run as root** — install via [nvm](https://github.com/nvm-sh/nvm) or the distro package, not via `sudo npm` |

> **Why no `sudo make`?** The portal frontend build calls `npm`, which refuses to run as root by default. Running `sudo make` causes the portal build to fail even if Docker works. The correct fix is to add your user to the `docker` group (see below) so you can run `make` as your regular user.

## Quickstart variants

```bash
make pki                # Generate dev PKI (CA + cert per NF) — first time only

make ueransim           # Core + obs + gNB + UE_COUNT UEs (default 1)
make full               # Everything: 13 NFs + obs + portal + 4 multi-slice UEs
make portal             # Core + observability + portal (no UERANSIM)
make ueransim-slices    # Core + obs + 4 UEs multi-slice (no portal)
make up-obs             # Core + observability only
make up                 # Core only

make down               # Stop and remove volumes (core / ueransim / portal variants)
make full-down          # Same, for the full stack
```

| Service | URL | Notes |
|---------|-----|-------|
| Portal | http://localhost:8080 | Centralized web management |
| Grafana | http://localhost:3000 | Dashboards (admin/admin, dev only) |
| Jaeger | http://localhost:16686 | Distributed tracing |
| Prometheus | http://localhost:9090 | Raw metrics |
| Loki | via Grafana | Structured JSON logs |

## Troubleshooting

### Docker permission denied — `make` fails on `docker build`

**Symptom:**
```
ERROR: permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock
```

**Cause:** Your user is not in the `docker` group.

**Fix:**
```bash
sudo usermod -aG docker $USER   # add yourself to the docker group
newgrp docker                   # activate the new group in the current shell
make full                       # retry — no sudo needed
```

If `newgrp docker` does not help, log out and back in, then retry.

> Do **not** use `sudo make`. That breaks the portal's npm build step.

## Make reference (by domain)

Run `make help` for the full, always-current list. The main groups:

### Full stack

| Command | Description |
|---------|-------------|
| `make full` | **Build + bring up ALL**: NFs + observability + portal + UERANSIM 4 UEs multi-slice |
| `make full-down` | Stop and clean volumes for full stack |

### Core and observability

| Command | Description |
|---------|-------------|
| `make up` | Bring up core (NFs) only |
| `make up-obs` | Bring up core + observability (Loki, Prometheus, Grafana, Jaeger) |
| `make down` | Stop all and clean volumes |

### Management portal

| Command | Description |
|---------|-------------|
| `make portal` | Build image + bring up core + obs + portal |
| `make docker-portal` | Build portal Docker image only |
| `make portal-build` | Alias for `docker-portal` |

### UERANSIM

| Command | Description |
|---------|-------------|
| `make ueransim` | Bring up core + obs + UERANSIM (gNB + N UEs). Accepts `UE_COUNT=N` |
| `make ueransim-ursp` | Build + bring up the full core + obs + UERANSIM **with URSP delivery** (default) |
| `make ueransim-no-ursp` | Build + bring up the full core + obs + UERANSIM **without URSP delivery** |
| `make ueransim-only` | Bring up UERANSIM only (without touching core). Accepts `UE_COUNT=N` |
| `make ueransim-down` | Stop UERANSIM containers |
| `make ueransim-slices` | Bring up core + obs + 4 UEs multi-slice (internet/gold/silver/bronze) |
| `make ueransim-slices-down` | Stop multi-slice profile containers |
| `make ueransim-profile-a` | Bring up core + obs + gNB + SUCI Profile A UE (X25519 ECIES, TS 33.501 §C.3) |
| `make ueransim-profile-a-down` | Stop SUCI Profile A containers |
| `make logs-slices` | Tail logs from 4 multi-slice UEs |
| `make test-slices` | Run T0–T9 validation suite |

### Xn & N2 handover

| Command | Description |
|---------|-------------|
| `make handover-test` | Core + obs + PacketRusher Xn handover scenario (TS 23.502 §4.9.1.2) |
| `make handover-n2-test` | Core + obs + PacketRusher N2 handover scenario (TS 23.502 §4.9.1.3) |
| `make handover-down` | Stop Xn handover profile containers |
| `make handover-n2-down` | Stop N2 handover profile containers |

### Build and tests

| Command | Description |
|---------|-------------|
| `make build` | Build all NFs |
| `make test` | Unit tests for all NFs |
| `make lint` | golangci-lint for all NFs |
| `make docker` | Build all Docker images |
| `make pki` | Generate dev PKI (CA + cert per NF) |

## Compile with / without URSP policy delivery

The full core can be built and run in two scenarios so you can compare behaviour
with and without **URSP** (UE Route Selection Policy) delivery. Both targets
rebuild the images and bring up core + observability + UERANSIM — they differ only
in whether the AMF requests URSP from the PCF (N15) and delivers a UE policy
container to the UE.

| Command | Scenario |
|---------|----------|
| `make ueransim-ursp` | **With URSP** — AMF fetches URSP over N15 and delivers it via DL NAS Transport (payload container type `0x05`, a MANAGE UE POLICY COMMAND per TS 24.501 Annex D) |
| `make ueransim-no-ursp` | **Without URSP** — AMF makes no N15 call and delivers no UE policy container; the rest of the core runs identically |

Both accept `UE_COUNT=N`. The PCF keeps serving SM policy (N7) in both scenarios;
only URSP delivery is toggled.

```bash
# With URSP (default behaviour)
make ueransim-ursp
docker logs amf | grep "UE policy container sent"     # confirms delivery

# Without URSP
make ueransim-no-ursp
docker logs amf | grep "URSP delivery disabled"       # confirms it is off
```

**How the toggle works.** The AMF reads the `URSP_ENABLED` environment variable
(default `true`), which the two make targets set for you. You can also flip it on
any compose command, or persist it in the AMF config:

```bash
URSP_ENABLED=false make up-obs        # ad-hoc, any target
```
```yaml
# nf/amf/config/dev.yaml
features:
  ursp_enabled: false                 # env var overrides this
```

Resolution order: `URSP_ENABLED` env → `features.ursp_enabled` in the AMF config →
default (enabled).

> **Note:** UERANSIM v3.2.8 does not implement the UE policy delivery service, so in
> the *with URSP* scenario it logs `Unhandled DL NAS Transport payload container
> type [5]` and does not ACK. The AMF still emits a spec-correct, Wireshark-decodable
> PDU; a real UE would apply the rules and reply with MANAGE UE POLICY COMPLETE.
> Decode the container with `python3 scripts/decode-ursp.py` (see `make validate-ursp`).
> The repo's UERANSIM patch set (`tools/ueransim/`) adds URSP evaluation for the simulator.

## Security debug flags (AMF)

The AMF config (`nf/amf/config/dev.yaml`) exposes a `security:` block with optional
overrides for development and Wireshark tracing. **Never enable these in production.**

### `null_ciphering` — NEA0 no-encryption mode

```yaml
# nf/amf/config/dev.yaml
security:
  null_ciphering: true   # default: false
```

When `true`, the AMF negotiates **NEA0** (null ciphering) with every UE during the
Security Mode Command (TS 33.501 §6.7.2). Integrity protection continues to use the
best algorithm the UE supports (NIA2 or NIA1) — IA0 is never selected alongside EA0
in non-emergency registrations as required by TS 33.501 §6.7.2. The result: NAS
payloads are sent and received as plain text, so **Wireshark decodes them without any
key export or NAS decryption plugin**. Downlink NAS still carries security header type
`0x02` (integrity protected and ciphered) even with EA0, per TS 24.501 §4.4.5 — real UEs
discard any other type after Security Mode Complete.

> **Why keep integrity on?** TS 33.501 §6.7.2 forbids the combination EA0+IA0 in
> normal registrations. UERANSIM enforces this and would reject a Security Mode Command
> that proposed both null ciphering and null integrity. Keeping NIA2/NIA1 satisfies the
> spec while still giving you unencrypted NAS for capture analysis.

**How to enable:** set `null_ciphering: true` in `nf/amf/config/dev.yaml`, then rebuild
and restart:

```bash
make docker && make ueransim

# Confirm it is active:
docker logs amf | grep "null_ciphering"
# Expected: {"level":"WARN","nf":"AMF","msg":"null_ciphering enabled — NEA0 forced; production use forbidden"}
```

**How to disable:** set `null_ciphering: false` (or remove the key) and rebuild/restart
the same way.

> **Never enable in production.** With null ciphering active, all NAS traffic
> (including authentication vectors and NAS PDUs) is transmitted in the clear over the
> air interface.

## Network slicing

Four development slices (TS 23.501 §5.15):

| Slice | SST | SD | Type | Assigned IMSI |
|-------|-----|----|------|---------------|
| internet | 1 | 000001 | eMBB default | imsi-001010000000001 |
| gold | 1 | 000002 | eMBB premium | imsi-001010000000002 |
| silver | 2 | 000001 | URLLC | imsi-001010000000003 |
| bronze | 3 | 000001 | MIoT | imsi-001010000000004 |

```bash
make ueransim-slices      # core + obs + 4 UEs
make test-slices          # suite T0–T9 (wait ~2 min)
make logs-slices          # tail logs

# Or manage from the portal:
make portal               # http://localhost:8080/ueransim
```

### How NSSAI validation works (TS 23.502 §4.2.2.2.2 + §4.2.9)

1. UE sends `RequestedNSSAI` in Registration Request.
2. AMF calls NSSF (`GET /nnssf-nsselection/v2/...`) with requested NSSAI.
3. NSSF returns intersection with config's `allowed_slices`.
4. AMF intersects NSSF result with UDM subscription → `AllowedNSSAI`.
5. Empty `AllowedNSSAI` → log `NSSAI_NOT_ALLOWED`.

## UERANSIM

### Single UE mode

```bash
# First time (builds everything)
make ueransim

# Subsequent times (launch only, faster)
make ueransim-only

# Multiple UEs (UDR auto-seeds N subscribers)
make ueransim UE_COUNT=4

# Verify registration
docker exec ueransim-ue nr-cli --dump
docker exec ueransim-ue ip a | grep uesimtun

# Bring down
make down
```

Changing `UE_COUNT` requires `make ueransim` (not `ueransim-only`) so the UDR is re-seeded.

### SUCI Profile A (X25519 ECIES)

Validates SUCI deconcealment with protection scheme 1 (TS 33.501 §C.3). The UE sends a SUCI instead of a plaintext SUPI; UDM decrypts it using the home network private key.

```bash
# CLI
make ueransim-profile-a
docker logs ueransim-ue-profile-a        # confirm MM-REGISTERED
docker logs udm | grep "SUCI Profile A"  # deconcealment in UDM
docker logs amf | grep "supi.*imsi"      # resolved SUPI in AMF
make ueransim-profile-a-down

# Portal — after make ueransim-profile-a (or make full) has created containers:
# http://localhost:8080/ueransim  →  Scenarios  →  SUCI Profile A  →  Start
```

The UE config is `config/ueransim/ue-profile-a.yaml` (`protectionScheme: 1`). The portal's
**Scenarios** panel lets you switch between Standard, Multi-Slice, and SUCI Profile A with one
click — it automatically stops conflicting containers before starting the new scenario.

### nr-cli commands

```bash
# From CLI (equivalent to using portal at /ueransim)
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-list"
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-establish default internet"
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "ps-release 1"
docker exec ueransim-ue nr-cli imsi-001010000000001 -e "deregister"
docker exec ueransim-ue nr-cli --dump    # list all active UEs
```

> The `/ueransim` portal executes these same commands via the Docker exec API.

## Unit and BDD tests

```bash
go test ./...
go test ./shared/nas/...              # NAS codec
go test ./nf/amf/internal/ngap/...   # NGAP codec AMF
go test ./nf/smf/internal/server/... # SMF handlers + N2SM APER
go test ./shared/crypto/...           # SUCI deconcealment, NIA2, NEA2

# BDD (godog)
cd nf/nrf && make test-functional                        # 3 in-process scenarios, no stack needed
make ueransim && cd nf/amf && E2E_TEST=1 make test-functional   # E2E; without E2E_TEST=1 → pending (exit 0)
```

The multi-slice T0–T9 suite and the per-feature validation recipes live in
[validation-commands.md](validation-commands.md).

## Create a new NF

```bash
./scripts/new-nf.sh <nfname>   # copy _template and rename
cd nf/<nfname>
# Follow the "Adding a New Network Function" checklist in CONTRIBUTING.md
make build && make test
```
