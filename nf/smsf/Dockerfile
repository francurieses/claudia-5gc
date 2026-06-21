ARG GO_VERSION=1.26.2
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY shared/ ./shared/
COPY nf/smsf/ ./nf/smsf/
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/smsf ./nf/smsf/cmd/smsf

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/smsf /bin/smsf
USER nonroot:nonroot
EXPOSE 8009 9110
ENV CONFIG_PATH=/etc/5gc/config.yaml
ENTRYPOINT ["/bin/smsf"]
