ARG GO_VERSION=1.26.2
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY shared/ ./shared/
COPY nf/upf/ ./nf/upf/
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/upf ./nf/upf/cmd/upf

# alpine provides iproute2 (ip) and iptables needed for TUN + NAT setup
FROM alpine:3.21
RUN apk add --no-cache iproute2 iptables
COPY --from=build /out/upf /bin/upf
EXPOSE 8805/udp 2152/udp 9107
ENV CONFIG_PATH=/etc/5gc/config.yaml
ENTRYPOINT ["/bin/upf"]
