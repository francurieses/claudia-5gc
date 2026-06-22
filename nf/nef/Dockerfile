ARG GO_VERSION=1.26.2
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY shared/ ./shared/
COPY nf/nef/ ./nf/nef/
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/nef ./nf/nef/cmd/nef

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/nef /bin/nef
USER nonroot:nonroot
EXPOSE 8011 9112
ENV CONFIG_PATH=/etc/5gc/config.yaml
ENTRYPOINT ["/bin/nef"]
