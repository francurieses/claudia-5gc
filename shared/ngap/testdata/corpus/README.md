<!-- tier: public -->
# NGAP equivalence corpus (REL19-4.4)

One vector per `*.hex` file: lowercase hex, trailing newline. Consumed by `shared/ngap/corpus_test.go`
(`TestCorpusRoundTrip`, `TestCorpusNoSUPI`) and `corpus_free5gc_test.go` (new codec vs
`github.com/free5gc/ngap`; deleted with that dependency in REL19-4.5).

| Prefix | Content | Produced by |
|---|---|---|
| `amf-<Message>[-<variant>]` | NGAP-PDU built by an AMF `Build*` function | `NGAP_CORPUS_WRITE=1 go test ./nf/amf/internal/ngap -run TestCorpusGenAMF` |
| `smf-<TransferType>-<variant>` | N2 SM transfer (aper, `valueExt`) as built/consumed by the SMF | `NGAP_CORPUS_WRITE=1 go test ./nf/smf/internal/server -run TestCorpusGenSMF` |
| `pcap-<Procedure>-<kind>-<sha8>` | NGAP-PDU exported from local `pcaps/amf/*.pcap` (git-ignored) via `tshark -T json -j ngap -x` | `scripts/ngap-corpus-from-pcap.sh` (`tools/ngapcorpus`) |

`REL17PLUS` lists vectors free5gc/ngap v1.1.3 (pre-Rel-17 ASN.1) cannot decode, each with a reason;
every other vector must re-encode identically with both codecs. An unlisted free5gc failure, or a
stale entry, fails the test.

## Sanitisation rule

Only hex vectors are committed, never pcaps. No SUPI in clear: `tools/ngapcorpus` overwrites the MSIN
digits of every null-scheme SUCI (NAS 5GS mobile identity, TS 24.501 §9.11.3.4) in place with `0`
filler (same length, PER stays valid) and re-decodes each PDU. `TestCorpusNoSUPI` asserts that no
vector contains the BCD of a known test MSIN and that every null-scheme SUCI carries filler only.
