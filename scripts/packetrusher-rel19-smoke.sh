#!/usr/bin/env bash
# packetrusher-rel19-smoke.sh - REL19-8.2 smoke: PacketRusher `--release rel19 ue` registers against the AMF.
#
# Prerequisite: `make up RAN=packetrusher PR_SCENARIO=none` (core up, packetrusher image built, containers
# created but NOT started). The script runs a one-off container from the compose `packetrusher` service
# (same networks/IPs/config; docker-compose.yml is not touched) with an alternative command, waits for the
# registration, prints the PacketRusher rel19 decode lines and the AMF registration lines, then removes it.
# Do not run it while `packetrusher` / `packetrusher-n2` are running (they share static IPs).
#
# Env: SUPI (default imsi-001010000000101), WAIT (seconds, default 25), PCAP=<file> to capture the AMF's
# SCTP (N2) with a netshoot sidecar sharing the AMF netns.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

SUPI="${SUPI:-imsi-001010000000101}"
WAIT="${WAIT:-25}"
NAME="packetrusher-rel19-smoke"
COMPOSE="docker compose"

docker rm -f "$NAME" >/dev/null 2>&1 || true
CAP=""
if [ -n "${PCAP:-}" ]; then
  mkdir -p "$(dirname "$PCAP")"
  docker rm -f "$NAME-pcap" >/dev/null 2>&1 || true
  docker run -d --name "$NAME-pcap" --net container:amf --cap-add NET_ADMIN --cap-add NET_RAW \
    nicolaka/netshoot tcpdump -i any -U -w "/tmp/smoke.pcap" sctp >/dev/null
  CAP=1
fi
SINCE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# Brief delay lets AMF listen / the capture start; then the one-off rel19 run.
$COMPOSE --profile handover run -d --no-deps --name "$NAME" packetrusher \
  --config /config/packetrusher.yaml --release rel19 ue --disableTunnel >/dev/null
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true; [ -n "$CAP" ] && docker rm -f "$NAME-pcap" >/dev/null 2>&1 || true' EXIT

ok=0
for _ in $(seq 1 "$WAIT"); do
  # Capture first: `docker logs | grep -q` under pipefail fails on SIGPIPE once grep exits early.
  logs="$(docker logs "$NAME" 2>&1 || true)"
  if grep -q "Registration Accept IEs" <<<"$logs"; then ok=1; break; fi
  sleep 1
done
sleep 2
echo "--- PacketRusher (rel19) ---"
docker logs "$NAME" 2>&1 | grep -E "rel19|Receive Registration|REGISTERED|PDU Session" | cut -c1-400 || true
echo "--- AMF (since $SINCE) ---"
docker logs --since "$SINCE" amf 2>&1 | grep -iE "Registration (Accept|Complete)|5GMM capab|capabilit" | grep -i "$SUPI\|registration\|capab" | cut -c1-400 | head -20 || true
if [ -n "$CAP" ]; then
  sleep 1; docker stop -t 3 "$NAME-pcap" >/dev/null; docker cp "$NAME-pcap:/tmp/smoke.pcap" "$PCAP" && echo "pcap: $PCAP"
fi
if [ "$ok" = 1 ]; then echo "SMOKE PASS: Registration Accept decoded in rel19 mode"; else echo "SMOKE FAIL: no Registration Accept within ${WAIT}s" >&2; exit 1; fi
