# PacketRusher (https://github.com/HewlettPackard/PacketRusher) — RAN/UE simulator
# used by make handover-test / handover-n2-test / RAN=packetrusher|both.
#
# Pinned to a known commit so builds are reproducible. Commits before acf96b5
# (e.g. 19a5800, 2026-10-02) call log.Fatal on any DL NAS TRANSPORT whose
# Payload container type is not "N1 SM information" (1). The AMF legitimately
# sends type 5 "UE policy container" (URSP, TS 24.501 §9.11.3.40, Annex D;
# TS 23.502 §4.2.4.3) right after registration, which killed the UE with
# "Payload Container Type not expected value" (backlog PR-001). From acf96b5
# PacketRusher logs "Invalid DL NAS Transport" and carries on.
# Bump PACKETRUSHER_REF deliberately and re-run both handover scenarios.
ARG GO_VERSION=1.26.2
FROM golang:${GO_VERSION}-alpine AS builder

ARG PACKETRUSHER_REF=acf96b571dff4b58d9f33d66a8cfd48dd1500620

RUN apk add --no-cache git build-base linux-headers

WORKDIR /src
RUN git init -q . \
    && git remote add origin https://github.com/HewlettPackard/PacketRusher.git \
    && git fetch -q --depth=1 origin "${PACKETRUSHER_REF}" \
    && git checkout -q FETCH_HEAD

RUN go mod download && CGO_ENABLED=0 go build -trimpath -o /packetrusher-bin ./cmd

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y iproute2 iputils-ping iputils-arping iperf3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /packetrusher-bin /usr/local/bin/packetrusher
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
