FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git build-base linux-headers

WORKDIR /src
RUN git clone --depth=1 https://github.com/HewlettPackard/PacketRusher.git .

RUN go mod download && cd cmd && CGO_ENABLED=0 go build -o /packetrusher-bin

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y iproute2 iputils-ping iperf3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /packetrusher-bin /usr/local/bin/packetrusher
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
