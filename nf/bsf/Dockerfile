ARG GO_VERSION=1.26.2
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY shared/ ./shared/
COPY nf/bsf/ ./nf/bsf/
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/bsf ./nf/bsf/cmd/bsf

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/bsf /bin/bsf
USER nonroot:nonroot
EXPOSE 8010 9111
ENV CONFIG_PATH=/etc/5gc/config.yaml
ENTRYPOINT ["/bin/bsf"]
