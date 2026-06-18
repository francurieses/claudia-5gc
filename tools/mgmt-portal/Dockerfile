# Stage 1: build React SPA
FROM node:22-alpine AS web-builder
WORKDIR /app/web
COPY web/package.json web/package-lock.json* ./
RUN npm install
COPY web/ ./
RUN npm run build
# Output is in /app/internal/assets/static (outDir = '../internal/assets/static')

# Stage 2: build Go binary
FROM golang:1.26.2-alpine AS go-builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Overlay the compiled React assets into the embed path
COPY --from=web-builder /app/internal/assets/static ./internal/assets/static
RUN go build -trimpath -ldflags="-s -w" -o /mgmt-portal ./cmd/mgmt-portal

# Stage 3: minimal runtime
FROM alpine:3.21
RUN apk --no-cache add ca-certificates tzdata
COPY --from=go-builder /mgmt-portal /mgmt-portal
EXPOSE 8080
ENTRYPOINT ["/mgmt-portal"]
