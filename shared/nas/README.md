# shared/nas — NAS-5GS codec (TS 24.501)

Phase 1 deliverable. Not yet implemented.

## Plan

Two viable paths:

1. **Reuse `github.com/free5gc/nas`** (Apache-2.0). Mature, complete, used in
   production by free5GC. Wrap with our logging/types conventions in
   `shared/nas/wrap.go`.
2. **Hand-roll** a minimal subset (Registration Request, Authentication
   Request/Response, Security Mode Command/Complete, Service Request, etc.)
   for educational purposes.

**Recommendation:** Reuse free5GC. Document the import in this README and add
the dependency in `shared/go.mod` when Phase 1 starts.

## Requirements

- Encode/decode all 5GMM messages per TS 24.501 §8.2.
- Encode/decode all 5GSM messages per TS 24.501 §8.3.
- NAS security: ciphering (NEA0/1/2/3) and integrity (NIA0/1/2/3) per §4.4.
- SUCI handling: encoding per §9.11.3.4, schemes per TS 33.501 Annex C.

## Tests

Property-based encode→decode→equal tests with `gopter`. Vector-based tests
using PCAPs from UERANSIM as ground truth.
