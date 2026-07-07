ARG UERANSIM_VERSION=v3.2.8

# ---- build -------------------------------------------------------------------
FROM ubuntu:22.04 AS build

ARG UERANSIM_VERSION
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        wget \
        patch \
        cmake \
        g++ \
        make \
        libsctp-dev \
        lksctp-tools \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

RUN wget -qO- \
    "https://github.com/aligungr/UERANSIM/archive/refs/tags/${UERANSIM_VERSION}.tar.gz" \
    | tar -xz --strip-components=1

# Apply the 5GC modification patch set, in numeric order, over stock UERANSIM.
# Each patch is a portable unified diff (git-style a/ b/ prefixes → patch -p1) so
# the modded UE can be reproduced on any deployment by dropping in patches/.
# See tools/ueransim/CLAUDE.md for the per-feature catalogue and dev workflow.
#   0001 — skip unknown optional NAS IEs (TS 24.007 §11.2.4) instead of crashing
#   0010 — URSP / UE policy delivery service (TS 24.501 Annex D, TS 24.526)
#   0020 — URSP rule evaluation + autonomous session + nr-cli verbs
#          (ursp-show / ursp-match / ursp-establish / ps-modify)
#   0030 — NW-initiated PDU session modification: UE 0xCB→0xCC handler + gNB
#          NGAP PDUSessionResourceModify forwarding (TS 23.502 §4.3.3.2)
#   0040 — gNB NGAP LocationReportingControl → LocationReport (TS 38.413 §8.17)
#   0041 — gNB NRPPa E-CID transport, real ASN.1 APER (TS 38.455 §8/§9)
#   0042 — LPP A-GNSS UE responder: payload container type 3 (TS 24.501
#          §9.11.3.40) → TS 37.355 UNALIGNED-PER codec mirroring shared/lpp;
#          ProvideCapabilities / anchor-seeded synthetic GNSS measurements /
#          gnss-Error; LPP_GNSS_NONE=1 negative mode (docs/procedures/LPPRelay.md)
#   0050 — UE re-registration on NW-initiated deregistration with
#          "re-registration required" (TS 24.501 §5.5.2.3.2)
#   0051 — gNB AMF selection fallback for initial NAS messages without a
#          Requested NSSAI (Service Request from CM-IDLE, secured Registration
#          Update) — stock selectAmf drops them with "AMF selection failed"
COPY tools/ueransim/patches/ /patches/
RUN set -e; for p in /patches/*.patch; do \
        echo "Applying $p"; \
        patch -p1 --no-backup-if-mismatch < "$p"; \
    done

RUN cmake -DCMAKE_BUILD_TYPE=Release -G "CodeBlocks - Unix Makefiles" . -B cmake-build && \
    cmake --build cmake-build --target all -- -j"$(nproc)" && \
    mkdir -p /out && \
    cp cmake-build/nr-gnb cmake-build/nr-ue cmake-build/nr-cli /out/ && \
    cp cmake-build/libdevbnd.so /out/ && \
    cp tools/nr-binder /out/

# ---- runtime -----------------------------------------------------------------
FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libsctp1 \
        iproute2 \
        iptables \
        iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/ /ueransim/

ENV PATH="/ueransim:${PATH}"

WORKDIR /ueransim
