#!/bin/sh
set -e

# PacketRusher's handover mode creates two gNBs by incrementing both the
# N2 (control/SCTP) and N3 (data/GTP-U) IPs by 1:
#   gNB1: controlif=172.30.1.20  dataif=172.30.3.10
#   gNB2: controlif=172.30.1.21  dataif=172.30.3.11
# We add the secondary addresses before PacketRusher starts so both SCTP
# binds succeed. N2 is on the same bridge as AMF so no cross-bridge ARP issues.

N2_IFACE=$(ip -o -4 addr | awk '/172\.30\.1\./{print $2; exit}')
N3_IFACE=$(ip -o -4 addr | awk '/172\.30\.3\./{print $2; exit}')

[ -n "$N2_IFACE" ] && ip addr add 172.30.1.21/24 dev "$N2_IFACE" 2>/dev/null || true
[ -n "$N3_IFACE" ] && ip addr add 172.30.3.11/24 dev "$N3_IFACE" 2>/dev/null || true

exec packetrusher "$@"
