ARG GO_VERSION=1.26.2
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY shared/ ./shared/
# Private-edition sources (dev/rel19/PLAN.md §1.2): the glob copies private/ when it
# exists (private repo) and matches nothing in the public snapshot, which strips both
# private/ and the *_private.go bridges, so one Dockerfile builds both editions.
# Build stage only: nothing from private/ is copied into the runtime image beyond the binary.
COPY privat[e]/ ./private/
COPY nf/upf/ ./nf/upf/
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/upf ./nf/upf/cmd/upf

# alpine provides iproute2 (ip) and iptables needed for TUN + NAT setup
FROM alpine:3.24
RUN apk add --no-cache iproute2 iptables
COPY --from=build /out/upf /bin/upf
EXPOSE 8805/udp 2152/udp 9107
ENV CONFIG_PATH=/etc/5gc/config.yaml
ENTRYPOINT ["/bin/upf"]
