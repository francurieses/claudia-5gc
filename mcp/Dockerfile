# MCP server — multi-stage Dockerfile.
# Static binary shipped in distroless. Build context is the repo root so the
# root module (and shared/ packages) resolve.

ARG GO_VERSION=1.26.2

# ---- build ---------------------------------------------------------------
FROM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

# Root module so shared/ resolves.
COPY go.mod go.sum* ./
RUN go mod download

# Shared packages and MCP source (MCP imports shared/, not the other NFs).
COPY shared/ ./shared/
COPY mcp/ ./mcp/

ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/mcp ./mcp/cmd/mcp

# ---- runtime -------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /
COPY --from=build /out/mcp /bin/mcp

USER nonroot:nonroot
EXPOSE 9300

ENV CONFIG_PATH=/etc/5gc/config.yaml
ENV HEALTHCHECK_ADDR=http://127.0.0.1:9300/mcp/health

ENTRYPOINT ["/bin/mcp"]
