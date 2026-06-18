# NRF — multi-stage Dockerfile
# Build a static binary, ship in distroless. ~20MB final image.

ARG GO_VERSION=1.26.2

# ---- build ---------------------------------------------------------------
FROM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

# Use the root module so shared/config (and other shared packages) resolve.
COPY go.mod go.sum* ./
RUN go mod download

# Copy shared packages and NRF source.
COPY shared/ ./shared/
COPY nf/nrf/ ./nf/nrf/

# Remove NRF's standalone go.mod so the root module takes over.
# NRF's own go.mod was used for isolated local development; all deps are
# already declared in the root go.mod.
RUN rm -f ./nf/nrf/go.mod ./nf/nrf/go.sum

# Static build
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/nrf ./nf/nrf/cmd/nrf

# ---- runtime -------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /
COPY --from=build /out/nrf /bin/nrf

USER nonroot:nonroot
EXPOSE 8000 9100

ENV CONFIG_PATH=/etc/5gc/config.yaml
ENV HEALTHCHECK_ADDR=https://127.0.0.1:8000/healthz

ENTRYPOINT ["/bin/nrf"]
