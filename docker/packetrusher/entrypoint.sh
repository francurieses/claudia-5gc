#!/bin/sh
set -e

# PacketRusher's handover mode creates two gNBs by incrementing both the
# N2 (control/SCTP) and N3 (data/GTP-U) IPs by 1:
#   gNB1: controlif=172.30.1.20:9487  dataif=172.30.3.10:2152
#   gNB2: controlif=172.30.1.21:9488  dataif=172.30.3.11:2152
# We add the secondary addresses before PacketRusher starts so both SCTP
# binds succeed. N2 is on the same bridge as AMF so no cross-bridge ARP issues.
#
# Coexistence with UERANSIM (RAN=both, backlog PR-002): every simulator runs in
# its own network namespace, so local ports never collide; what must be unique
# is the IP address (and the Global gNB ID). UERANSIM's gNBs take a dynamic N2
# address and 172.30.3.3 / 172.30.3.4 on N3; PacketRusher owns .20/.21 (N2)
# and .10/.11 (N3). GTP-U stays on UDP 2152 — the UPF sends G-PDUs to that
# port (TS 29.281 §4.4.2.3), so it is not a per-simulator knob.

N2_IFACE=$(ip -o -4 addr | awk '/172\.30\.1\./{print $2; exit}')
N3_IFACE=$(ip -o -4 addr | awk '/172\.30\.3\./{print $2; exit}')

HAVE_ARPING=0
command -v arping >/dev/null 2>&1 && HAVE_ARPING=1

# add_secondary IFACE ADDR — add ADDR/24 to IFACE. The secondary addresses are
# not reserved in Docker IPAM, so first probe the bridge (ARP duplicate address
# detection) and refuse to start if another container already holds ADDR.
add_secondary() {
    iface=$1
    addr=$2
    [ -n "$iface" ] || return 0
    if [ "$HAVE_ARPING" = 1 ] && ! arping -q -D -c 2 -w 3 -I "$iface" "$addr" >/dev/null 2>&1; then
        echo "packetrusher-entrypoint: $addr is already in use on $iface (another container holds it);" \
             "the second handover gNB cannot start. Free the address or change the PacketRusher IPs." >&2
        exit 1
    fi
    ip addr add "$addr/24" dev "$iface" 2>/dev/null || true
    # A recreated container gets a new MAC, but the AMF/UPF neighbour caches
    # still map ADDR to the previous container's MAC for a while, so the second
    # gNB's SCTP INIT-ACK (and GTP-U) goes nowhere ("SCTP dial timeout").
    # Announce the address with gratuitous ARP.
    if [ "$HAVE_ARPING" = 1 ]; then
        arping -q -U -c 2 -I "$iface" "$addr" >/dev/null 2>&1 || true
    fi
}

add_secondary "$N2_IFACE" 172.30.1.21
add_secondary "$N3_IFACE" 172.30.3.11

exec packetrusher "$@"
