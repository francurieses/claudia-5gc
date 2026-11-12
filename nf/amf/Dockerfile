ARG GO_VERSION=1.26.2
FROM golang:${GO_VERSION} AS build
WORKDIR /src
RUN apt-get update && apt-get install -y libsctp-dev lksctp-tools
COPY go.mod go.sum* ./
RUN go mod download
COPY shared/ ./shared/
# Private-edition sources (dev/rel19/PLAN.md §1.2): the glob copies private/ when it
# exists (private repo) and matches nothing in the public snapshot, which strips both
# private/ and the *_private.go bridges, so one Dockerfile builds both editions.
# Build stage only: nothing from private/ is copied into the runtime image beyond the binary.
COPY privat[e]/ ./private/
COPY nf/amf/ ./nf/amf/
ENV CGO_ENABLED=1
RUN go build -ldflags="-s -w" -o /out/amf ./nf/amf/cmd/amf

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libsctp1 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/amf /bin/amf
EXPOSE 38412 8001 9101
ENV CONFIG_PATH=/etc/5gc/config.yaml
ENTRYPOINT ["/bin/amf"]
