# CLAUDE.md — UERANSIM (modified UE/gNB simulator)

> Read the root `CLAUDE.md` first for global conventions.

## 1. Purpose

UERANSIM v3.2.8 is our RAN+UE simulator for end-to-end testing. Stock v3.2.8 lacks UE-side
support for several procedures our core implements, so we **patch** it. This directory builds a
modified image (`5gc/ueransim:dev`) from the upstream tarball plus an ordered set of portable
patches.

The **patch set is the committed artifact** — not a vendored source tree, not a submodule. This
keeps the repo small and lets anyone reproduce the modded UE on any deployment by dropping
`patches/` into the build.

## 2. Layout

```
tools/ueransim/
  Dockerfile          Downloads v3.2.8 tarball, applies patches/*.patch in order, builds.
  patches/            Ordered unified diffs (git-style a/ b/ prefixes, applied with patch -p1).
  dev/clone-fork.sh   Sets up a throwaway .fork/ source tree for C++ development.
  .fork/              (git-ignored) full UERANSIM source for developing/compiling. Not committed.
```

## 3. Patch catalogue

| Patch | Feature | Spec | Core counterpart |
|---|---|---|---|
| `0001-skip-unknown-ie.patch` | Skip unknown optional NAS IEs instead of crashing | TS 24.007 §11.2.4 | — |
| `0010-ue-policy-delivery.patch` | URSP / UE policy delivery service: parse MANAGE UE POLICY COMMAND (payload container 0x05), store URSP, reply MANAGE UE POLICY COMPLETE | TS 24.501 Annex D, TS 24.526 | PCF `internal/policy/ursp.go`; AMF UL NAS 0x05 handler (`handleUEPolicyDelivery`) |
| `0020-ursp-evaluation-and-nrcli.patch` | URSP rule matching (`MatchUrspTarget`) + autonomous URSP-steered PDU session; all new nr-cli verbs: `ursp-show`, `ursp-match`, `ursp-establish`, `ps-modify` | TS 23.503 §6.6.2, TS 24.526 §5.2 | NW-triggered PDU session flow |
| `0030-pdu-session-modification.patch` | UE-side PDU SESSION MODIFICATION COMMAND (0xCB) handler → reply COMPLETE (0xCC) **and** gNB-side NGAP `PDUSessionResourceModify` forwarding (stock UERANSIM gNB drops it as "Unhandled NGAP initiating-message"); the layers behind `ps-modify` and NW-initiated QoS | TS 23.502 §4.3.3, TS 38.413 §8.2.1 | SMF nsmf-management QoS (PTI=0); AMF 0xCB dispatch + 0xCC handler |

Patches are applied in filename order; the build fails hard on any reject. The split is by
concern: `0020` is the URSP/CLI layer, `0030` is the SM modification protocol — they touch
disjoint files so they apply independently (the CLI in `0020` calls into the SM methods added by
`0030`; both are applied before the single cmake build, so order only matters for `patch`, not for
the compiler). Keep the numeric prefixes spaced (0001/0010/0020…) so patches can be inserted
between them later.

## 4. Wire-format source of truth

The UE-side codecs added by these patches must byte-match what the core emits. The authoritative
references are the **Go encoders in the core**, not the (sometimes stale) prose in NF CLAUDE.md:

- **URSP / UE policy container** (MANAGE UE POLICY COMMAND): `nf/pcf/internal/policy/ursp.go`
  and the cross-check decoder `scripts/decode-ursp.py`.
- **DL/UL NAS Transport** (payload container LV-E, optional IEs): `shared/nas/transport.go`.
- **PDU session modification** (0xCB IEs 0x2A/0x7A/0x79): `shared/nas/pdu_session.go`.

## 5. Dev workflow (adding/editing a feature)

```bash
# 1. Set up a compilable source tree with the current patch set applied:
tools/ueransim/dev/clone-fork.sh          # creates tools/ueransim/.fork/

# 2. Develop in .fork (real compiler/IDE). Build natively if cmake is available:
cd tools/ueransim/.fork && cmake -B build . && cmake --build build -j

# 3. Export your changes to a numbered patch (full diff vs stock v3.2.8):
git diff > ../patches/00NN-my-feature.patch

# 4. Rebuild the image the CI way (applies all patches from scratch over a fresh tarball):
make ueransim-build-only                  # must apply cleanly — no .rej

# 5. Run end-to-end against the core:
make ueransim
```

To refresh an existing patch after editing: regenerate the whole `git diff` (the working tree in
`.fork` holds every patch applied, so `git diff` is the cumulative set — split per feature with
`git diff -- <paths>` when needed).

## 6. UERANSIM source map (where patches land)

- `src/lib/nas/` — NAS message structs + `encode.cpp`/decode (0001 lives here; 0010/0030 add msgs).
- `src/ue/nas/mm/transport.cpp` — DL/UL NAS Transport handling (payload container dispatch).
- `src/ue/nas/sm/` — Session Management: establish/release/**modify**.
- `src/ue/nas/` — UE NAS context (where stored URSP rules live).
- `src/ue/app/` + `src/lib/app/` + nr-cli option parser — `nr-cli` command definitions.

## 7. Caveats

- The UE responses these patches add (MANAGE UE POLICY COMPLETE, PDU SESSION MODIFICATION
  COMPLETE) only do something useful if the **core consumes them** — verify the AMF/SMF inbound
  handlers exist before declaring a feature done (see the table in §3).
- `.fork/` is disposable. Never commit it. The truth is in `patches/`.
