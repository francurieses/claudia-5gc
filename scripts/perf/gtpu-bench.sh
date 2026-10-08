#!/usr/bin/env bash
# scripts/perf/gtpu-bench.sh — UERANSIM-bypass UPF saturation sweep (Objective 3, answer B).
# Drives tools/gtpu-bench (fake SMF+gNB on N3, DN sink/sender on N6) through a pps ladder and
# reports the knee: the highest offered rate with >= MIN_DELIVERY delivered and 0 UPF drops.
# Usage: gtpu-bench.sh [--dir ul|dl|bidir] [--sessions "1 4 16"] [--sizes "1400 64"]
#                      [--ladder "5000 10000 ..."] [--duration 8] [--workers 2] [--build]
# Env: MIN_DELIVERY (default 0.99)
set -uo pipefail
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

DIRS="ul dl"; SESSIONS="1 4 16"; SIZES="1400 64"; DUR=8; WORKERS=2; BUILD=0
LADDER="5000 10000 20000 40000 80000 160000 320000"
MIN_DELIVERY="${MIN_DELIVERY:-0.99}"
while [ $# -gt 0 ]; do
    case "$1" in
        --dir) DIRS="$2"; shift ;; --sessions) SESSIONS="$2"; shift ;; --sizes) SIZES="$2"; shift ;;
        --ladder) LADDER="$2"; shift ;; --duration) DUR="$2"; shift ;; --workers) WORKERS="$2"; shift ;;
        --build) BUILD=1 ;; *) echo "unknown arg $1" >&2; exit 2 ;;
    esac; shift
done
require_cmds docker jq awk

[ "$BUILD" = 1 ] && docker compose --profile core --profile perf build gtpu-bench >&2
docker compose --profile core --profile perf up -d --no-deps gtpu-bench gtpu-bench-dn >&2 || exit 1
UPF_N6="$(docker inspect -f '{{with index .NetworkSettings.Networks "5gc-n6"}}{{.IPAddress}}{{end}}' upf)"
docker exec gtpu-bench-dn ip route replace 10.60.0.192/26 via "$UPF_N6" || exit 1

# Pre-flight: refuse to run if a real UE already uses the reserved synthetic range 10.60.0.200-249.
for ue in $(docker ps --format '{{.Names}}' | grep -E '^ueransim-ue'); do
    if docker exec "$ue" ip -4 -o addr show 2>/dev/null | grep -qE 'inet 10\.60\.0\.(2[0-4][0-9])/'; then
        echo "a real UE uses the reserved range 10.60.0.200-249 — aborting" >&2; exit 3
    fi
done

RUN="$(perf_new_run gtpu-bench)"; perf_env_manifest "$RUN"
echo "dir,sessions,size,target_pps,sent_pps,recv_pps,recv_mbps,delivery,reordered,bad,send_errs,upf_cpu,rcvbuf_err_delta,upf_drops_delta" > "$RUN/bench.csv"

metric() { # name -> sum of the counter series on the UPF
    docker run --rm --network container:upf "$PERF_IMAGE" curl -s --max-time 3 http://127.0.0.1:9107/metrics \
        | awk -v m="$1" '$0 ~ "^"m {s+=$NF} END{printf "%d\n", s}'
}
rcvbuf() { docker run --rm --network container:upf "$PERF_IMAGE" awk '/^Udp:/ && !h{h=1; next} /^Udp:/{print $6}' /proc/net/snmp; }
fval() { jq -r "$2" "$1" 2>/dev/null; }

knee_file="$RUN/knee.txt"; : > "$knee_file"
for d in $DIRS; do
 for k in $SESSIONS; do
  for sz in $SIZES; do
   best=0; bestmbps=0
   for pps in $LADDER; do
     tag="${d}_k${k}_s${sz}_p${pps}"
     start=$(( $(date +%s) + 6 + k / 4 ))
     ul=false; dl=false; sendall=false
     case "$d" in ul) ul=true ;; dl) dl=true ;; bidir) ul=true; dl=true ;; esac
     dr0="$(metric fivegc_upf_packet_drops_total)"; rb0="$(rcvbuf)"
     docker exec gtpu-bench gtpu-bench -mode ran -sessions "$k" -size "$sz" -pps "$pps" -duration "${DUR}s" \
        -start-at "$start" -workers "$WORKERS" -gnb-n3 172.30.3.20 -ul="$ul" -dl=true -upf upf-n4.5gc.local:8805 \
        > "$RUN/$tag.ran.json" 2> "$RUN/$tag.ran.err" &
     p1=$!
     docker exec gtpu-bench-dn gtpu-bench -mode dn -sessions "$k" -size "$sz" -pps "$pps" -duration "${DUR}s" \
        -start-at "$start" -workers "$WORKERS" -send-dl="$dl" -listen :9000 \
        > "$RUN/$tag.dn.json" 2> "$RUN/$tag.dn.err" &
     p2=$!
     sleep $(( start - $(date +%s) + DUR / 2 )) 2>/dev/null
     cpu="$(docker stats --no-stream --format '{{.CPUPerc}}' upf | tr -d '%')"
     wait $p1 $p2
     dr1="$(metric fivegc_upf_packet_drops_total)"; rb1="$(rcvbuf)"
     # delivery: UL = dn.recv/ran.sent ; DL = ran.recv/dn.sent ; bidir = worse of both
     ulsent="$(fval "$RUN/$tag.ran.json" .sent_pkts)"; ulrecv="$(fval "$RUN/$tag.dn.json" .recv_pkts)"
     dlsent="$(fval "$RUN/$tag.dn.json" .sent_pkts)";  dlrecv="$(fval "$RUN/$tag.ran.json" .recv_pkts)"
     if [ -z "$ulsent" ] || [ -z "$dlsent" ]; then echo "step $tag failed: $(head -c 200 "$RUN/$tag.ran.err")" >&2; break; fi
     read -r deliv recvpps recvmbps sentpps < <(awk -v d="$d" -v us="$ulsent" -v ur="$ulrecv" -v ds="$dlsent" -v dr="$dlrecv" \
        -v sec="$DUR" -v sz="$sz" 'BEGIN{
          du=(us>0)?ur/us:1; dd=(ds>0)?dr/ds:1;
          if(d=="ul"){dl=du; r=ur; s=us} else if(d=="dl"){dl=dd; r=dr; s=ds} else {dl=(du<dd)?du:dd; r=ur+dr; s=us+ds}
          printf "%.4f %.0f %.1f %.0f\n", dl, r/sec, r/sec*sz*8/1e6, s/sec }')
     reord="$(( $(fval "$RUN/$tag.dn.json" .reordered) + $(fval "$RUN/$tag.ran.json" .reordered) ))"
     bad="$(( $(fval "$RUN/$tag.dn.json" .bad_format) + $(fval "$RUN/$tag.ran.json" .bad_format) ))"
     errs="$(( $(fval "$RUN/$tag.dn.json" .send_errors) + $(fval "$RUN/$tag.ran.json" .send_errors) ))"
     echo "$d,$k,$sz,$pps,$sentpps,$recvpps,$recvmbps,$deliv,$reord,$bad,$errs,${cpu:-0},$((rb1-rb0)),$((dr1-dr0))" | tee -a "$RUN/bench.csv" >&2
     ok=$(awk -v x="$deliv" -v m="$MIN_DELIVERY" -v dd="$((dr1-dr0))" 'BEGIN{print (x>=m && dd==0)?1:0}')
     if [ "$ok" = 1 ]; then best="$recvpps"; bestmbps="$recvmbps"; else break; fi
     sleep 2
   done
   echo "knee dir=$d sessions=$k size=$sz : ${best} pps  ${bestmbps} Mb/s (delivered, >=${MIN_DELIVERY}, 0 UPF drops)" | tee -a "$knee_file" >&2
  done
 done
done
echo "$RUN"
