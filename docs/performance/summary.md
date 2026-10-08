<!-- tier: public -->
# Performance summary

Headline user-plane throughput of the ClaudIA 5GC UPF. These are **lab figures** measured
against the environment below; the method, raw results and tuning findings are part of the
members documentation.

Single UPF instance, optimized build, Docker Desktop VM (10 vCPUs), 1400 B packets, ≥ 99 % delivered, 0 UPF drops:

| Traffic | Max throughput | Packets/s | UPF CPU |
|---|---|---|---|
| Downlink | ≈ 1.8 Gb/s (99 % delivered up to ≈ 2.2 Gb/s) | 160–198 k | ≈ 95–120 % of a core |
| Uplink | ≥ 2.7 Gb/s (generator-limited floor) | ≥ 244 k | ≈ 100 % of a core |
| Both at once | ≈ 3.6 Gb/s combined (1.8 up + 1.8 down); degrades at 4.4 Gb/s | 160 k each way | ≈ 1.5 cores |
| 64 B, both at once | ≥ 400 kpps combined (≈ 200 Mb/s; ladder-limited floor) | 200 k each way | ≈ 1.7 cores |

One UERANSIM UE: ≈ 102–115 Mb/s (UE-bound, linear to 4 UEs ≈ 410 Mb/s). Not claimed: carrier-grade numbers, > 16 sessions,
rate-limited (AMBR) traffic at scale (single-UE enforcement results are in the notes below), real-RAN behaviour. These are lab figures against the environment manifest below.

**Environment:** Docker Desktop on an Apple host (10 vCPUs, 8 GB). Figures are valid only
for that setup. The "knee" is the highest offered load with ≥ 99 % delivery and zero UPF drops;
"floor" means the traffic generator, not the UPF, was the limit.

**Reproduce:** `make perf-up`, then `make perf-bench` (UPF in isolation, synthetic sessions),
`make perf-dn` / `make perf-multi-ue` (real UEs through the UPF). Knobs: `n3.socket_buffer_bytes`,
`n6.tun_mtu`, `n6.tcp_mss_clamp` in the UPF config — see [`../configuration.md`](../configuration.md).
