# shared/pfcpx

Extension of `github.com/wmnsk/go-pfcp` v0.0.14 for TS 29.244 V19.x. go-pfcp knows IE types only up to 271 but keeps unknown IEs as opaque Type/Length/Payload, so this package adds:

| File | Content |
|---|---|
| `types.go` | IE type constants 272-403, names and the grouped-IE set (`groupedTypes`), generated from TS 29.244 V19.6.0 Table 8.1.2-1 (273 Spare and 381 "Can be used" are unassigned) |
| `ie.go` | `NewGrouped` / `ParseGrouped` / `FindChild` (work for types go-pfcp does not know), typed scalars: RAT Type (§8.2.186, 1 octet, extendable), Maximum Receive Unit (§8.2.195, fixed 2-octet integer), Group Id (§8.2.198, octet string), URI (§8.2.244, RFC 3986 octet string) |
| `features.go` | UP Function Features (Table 8.2.25-1, 87 bits, octets 5-15) and CP Function Features (Table 8.2.58-1, 11 bits, octets 5-6), `Feature.Set/Apply`, `NewUPFunctionFeatures(names...)`, `SetUPFeatures` |

Compatibility: for bits go-pfcp already exposes (`HasFTUP()` ...), `NewUPFunctionFeatures` output is byte-identical to `ie.NewUPFunctionFeatures` (`TestFeaturesMatchGoPFCP`). No NF imports this package yet (REL19-6.2 will).

## Spec source

Verified against TS 29.244 V19.6.0 (Table 8.1.2-1, Tables 8.2.25-1 and 8.2.58-1, §8.2.185/186/195/198/244). Differences from the Wireshark 4.6.9 dissector, which seeded the first version: type 273 is Spare; 277/279/302/304/310/311/315/316 use the table names (e.g. 279 is "Created L2TP Session", 311 "MBS Session N4 Information"); 274, 317, 330 and 347 are not grouped while 334 and the Rel-19 clause-7 tables are; UP bits PSUPRM (11/3), EPPPI, MPQUIC-UDP, UMN6IP (13/7) / UN6TU (13/8), UN6DM (14/2), ULM (15/3) and the rest of octets 14-15; CP bit PAPFD (6/3).

## Tests

`go test ./shared/pfcpx/...` checks every type 272-403, the grouped set, spec octet/bit spot checks, and includes a crafted-IE pcap decoded with `tshark` (skipped when tshark is absent).
