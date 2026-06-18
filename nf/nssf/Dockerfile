ARG GO_VERSION=1.26.2
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY shared/ ./shared/
COPY nf/nssf/ ./nf/nssf/
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/nssf ./nf/nssf/cmd/nssf

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/nssf /bin/nssf
USER nonroot:nonroot
EXPOSE 8007 9109
ENV CONFIG_PATH=/etc/5gc/config.yaml
ENTRYPOINT ["/bin/nssf"]
