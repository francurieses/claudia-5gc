## Summary

<!-- What changed and why. Backlog task id (e.g. REL19-3.3) and 3GPP reference [TS xx.xxx §x.x.x]. -->

## Gates (AGENTS.md)

- [ ] Gap verified real (no duplicate of existing code)
- [ ] `docs/procedures/<Procedure>.md` and `.feature` exist (procedure tasks)
- [ ] `make build && make test` pass (lint failures confirmed pre-existing if any)
- [ ] N1/N2/N4 changes: `make ueransim UE_COUNT=1` + PCAP-ANALYZER verdict not broken
- [ ] `docs/compliance-matrix.md` row added/updated
- [ ] Docs updated per `docs/DOC_MAP.md` (docs-keeper) and `make docs-check STRICT=1` exits 0
- [ ] Visibility: `visibility: private` work only in private path classes; `make release-leak-test` passes

## Hard stops

- [ ] No change to `docker-compose.yml` service definitions or `shared/crypto` / `shared/aka`, or a recorded sign-off is linked (`dev/REL19_PROGRAM.md` §4)

## Notes for reviewers

<!-- New dependencies (justification, GPL-3.0 compatibility), behaviour gated OFF by default, risks. -->
