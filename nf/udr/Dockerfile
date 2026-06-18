ARG GO_VERSION=1.26.2
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY shared/ ./shared/
COPY nf/udr/ ./nf/udr/
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/udr ./nf/udr/cmd/udr

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/udr /bin/udr
USER nonroot:nonroot
EXPOSE 8000 9100
ENV CONFIG_PATH=/etc/5gc/config.yaml
ENTRYPOINT ["/bin/udr"]
