ARG GO_VERSION=1.26.2
FROM golang:${GO_VERSION} AS build
WORKDIR /src
RUN apt-get update && apt-get install -y libsctp-dev lksctp-tools
COPY go.mod go.sum ./
RUN go mod download
COPY shared/ ./shared/
COPY nf/amf/ ./nf/amf/
ENV CGO_ENABLED=1
RUN go build -ldflags="-s -w" -o /out/amf ./nf/amf/cmd/amf

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libsctp1 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/amf /bin/amf
EXPOSE 38412 8001 9101
ENV CONFIG_PATH=/etc/5gc/config.yaml
ENTRYPOINT ["/bin/amf"]
