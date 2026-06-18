ARG GO_VERSION=1.26.2
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY shared/ ./shared/
COPY nf/pcf/ ./nf/pcf/
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/pcf ./nf/pcf/cmd/pcf

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/pcf /bin/pcf
USER nonroot:nonroot
EXPOSE 8006 9106
ENV CONFIG_PATH=/etc/5gc/config.yaml
ENTRYPOINT ["/bin/pcf"]
