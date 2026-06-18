# {{NF_NAME}} — multi-stage Dockerfile (template)
ARG GO_VERSION=1.22

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY nf/{{nf_name}}/go.mod nf/{{nf_name}}/go.sum* ./
RUN go mod download
COPY nf/{{nf_name}}/ ./
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/{{nf_name}} ./cmd/{{nf_name}}

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/{{nf_name}} /bin/{{nf_name}}
USER nonroot:nonroot
EXPOSE 8000 9100
ENV CONFIG_PATH=/etc/5gc/config.yaml
ENTRYPOINT ["/bin/{{nf_name}}"]
