#!/usr/bin/env bash
# scripts/perf/perf-report.sh <run-dir> — aggregate results.csv (or baseline.csv) into summary.csv + summary.md.
# Per (case, ues[, vantage, server]) group: reps, median/min/max of the per-rep AGGREGATE Mb/s
# (sum over the concurrent UEs of one rep), retransmits, loss, jitter.
set -uo pipefail
RUN="${1:?usage: perf-report.sh <run-dir>}"
SRC="$RUN/results.csv"; [ -f "$SRC" ] || SRC="$RUN/baseline.csv"
[ -f "$SRC" ] || { echo "no results.csv/baseline.csv in $RUN" >&2; exit 2; }
# normalise to: group,rep,mbps,retrans,loss,jitter   (group = case|ues|vantage|server)
if [ "$(basename "$SRC")" = results.csv ]; then
    awk -F, 'NR>1 && $1!~/#/{print $1"|ues="$8 "," $10 "," $2 "," $3 "," $4 "," $5}' "$SRC"
else
    awk -F, 'NR>1 && $1!~/#/{print $1"|"$8"|"$9 "," $10 "," $2 "," $3 "," $4 "," $5}' "$SRC"
fi | tr "|" "/" > "$RUN/.norm"
# sum per (group,rep) across UEs, then stats across reps
awk -F, '{k=$1 SUBSEP $2; m[k]+=$3; rt[k]+=$4; l[k]=($5>l[k]?$5:l[k]); j[k]=($6>j[k]?$6:j[k]); g[k]=$1; n[g[k]]++}
  END{for(k in m){ split(k,a,SUBSEP); print a[1] "," m[k] "," rt[k] "," l[k] "," j[k] }}' "$RUN/.norm" | sort -t, -k1,1 -k2,2n > "$RUN/.perrep"
awk -F, '
  function med(arr,n,  i,j,t){ for(i=2;i<=n;i++){t=arr[i];for(j=i-1;j>=1&&arr[j]>t;j--)arr[j+1]=arr[j];arr[j+1]=t}
                              return (n%2)?arr[(n+1)/2]:(arr[n/2]+arr[n/2+1])/2 }
  {g=$1; c[g]++; v[g,c[g]]=$2; rt[g]+=$3; if($4>lo[g])lo[g]=$4; if($5>ji[g])ji[g]=$5}
  END{ print "group,reps,median_mbps,min_mbps,max_mbps,retrans_avg,max_loss_pct,max_jitter_ms"
       for(g in c){ n=c[g]; for(i=1;i<=n;i++)a[i]=v[g,i]; m=med(a,n); mn=a[1]; mx=a[n]
         printf "%s,%d,%.1f,%.1f,%.1f,%.0f,%.2f,%.3f\n", g,n,m,mn,mx,rt[g]/n,lo[g],ji[g] } }' "$RUN/.perrep" | sort > "$RUN/summary.csv"
{
  echo "| group | reps | median Mb/s | min | max | retrans | loss % | jitter ms |"
  echo "|---|---|---|---|---|---|---|---|"
  tail -n +2 "$RUN/summary.csv" | awk -F, '{printf "| %s | %s | %s | %s | %s | %s | %s | %s |\n",$1,$2,$3,$4,$5,$6,$7,$8}'
} > "$RUN/summary.md"
rm -f "$RUN/.norm" "$RUN/.perrep"
cat "$RUN/summary.md"
