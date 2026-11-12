<!-- tier: public -->
# PacketRusher patches (claudia-5gc)

`docker/packetrusher/Dockerfile` checks out PacketRusher (Apache-2.0, pinned `PACKETRUSHER_REF`) and applies
`patches/*.patch` in order with `git apply`. The patches modify Apache-2.0 files; each carries the change notice
(Apache-2.0 section 4(b)); the patch text is GPL-3.0-or-later like the rest of claudia-5gc.

| Patch | Content |
|---|---|
| `0001-claudia-rel19-codec.patch` | `--release rel17\|rel19` (env `PACKETRUSHER_RELEASE`), `internal/claudia` package, `require/replace github.com/francurieses/claudia-5gc => ./third_party/claudia-5gc`, NAS plaintext observer hook, `Capability5GMM.Raw` |

## Vendoring (why not a copy of shared/ in the image context)
The compose build context is `./docker/packetrusher`, so repo-root `shared/` is unreachable.
`scripts/packetrusher-vendor.sh` (run by `make ran-up` and `make packetrusher-vendor`) stages `shared/{ngap,nas,capability}`
(no tests, testdata or `*_private*.go`) plus a generated `go.mod` into the gitignored `docker/packetrusher/claudia-vendor/`; the Dockerfile
copies it to `third_party/claudia-5gc`. Building the image by hand needs `make packetrusher-vendor` first.

PacketRusher's NGAP builders use `github.com/free5gc/ngap` v1.2.0 (`ie`/`message` API, a different codec from the
`ngapType` structs of `shared/ngap`), so the free5gc/ngap dependency is NOT replaced: rel17 traffic stays byte-identical, and `shared/ngap`
is used only to decode downlink PDUs in rel19 mode (log only).

## `--release rel19`
* Registration Request 5GMM capability IE: legacy bits (S1 mode, HO attach, LPP, N3 data) plus Rel-18 LADN-DS, NSR, PNS, TempNS, SLVI, NSUC
  and Rel-19 ATUC (9 octets). Only "can receive and ignore" bits; PacketRusher implements no behaviour behind them.
* Downlink Registration Accept: IEs listed with name and introducing release (unknown IEIs skipped per TS 24.007 11.2.4) and decoded
  with `shared/nas`; downlink NGAP PDUs decoded with `shared/ngap` (TS 38.413 V19); `claudia.ParsePDUSetInfo` decodes the GTP-U PDU Set
  Information container (ext header 0x04, TS 29.281 / TS 38.415 6.5). PacketRusher's data plane is the kernel gtp5g module, so the GTP-U
  decoder is a library (unit-tested) with no live hook: `claudia.ObserveGTPU` is never called by PacketRusher, because gtp5g terminates GTP-U in the kernel and user space never sees the packets.
* Smoke: `make up RAN=packetrusher PR_SCENARIO=none && scripts/packetrusher-rel19-smoke.sh` (`PCAP=file` captures the AMF N2).
