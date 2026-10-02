# Build stage
FROM golang:1.27-alpine3.24 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Generate swagger and build
# swag is declared as a tool in go.mod, so its version follows the module
RUN go tool swag init -g cmd/server/main.go -o docs
RUN CGO_ENABLED=0 GOOS=linux go build -o http-header-security-scanner ./cmd/server

# Runtime stage
FROM alpine:3.24

WORKDIR /app

RUN apk --no-cache add ca-certificates

COPY --from=builder /app/http-header-security-scanner .

# Port default
EXPOSE 8081

# Enviroments variables
ENV GIN_MODE=release
ENV SERVER_PORT=8081

CMD ["./http-header-security-scanner"]
