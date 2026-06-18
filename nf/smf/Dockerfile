ARG GO_VERSION=1.26.2
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY shared/ ./shared/
COPY nf/smf/ ./nf/smf/
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/smf ./nf/smf/cmd/smf

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/smf /bin/smf
USER nonroot:nonroot
EXPOSE 8004 9105
ENV CONFIG_PATH=/etc/5gc/config.yaml
ENTRYPOINT ["/bin/smf"]
