# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install swag to generate swagger
RUN go install github.com/swaggo/swag/cmd/swag@latest

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Generate swagger and build
RUN swag init -g cmd/server/main.go -o docs
RUN CGO_ENABLED=0 GOOS=linux go build -o http-header-security-scanner ./cmd/server

# Runtime stage
FROM alpine:3.19

WORKDIR /app

RUN apk --no-cache add ca-certificates

COPY --from=builder /app/http-header-security-scanner .

# Port default
EXPOSE 8081

# Enviroments variables
ENV GIN_MODE=release
ENV SERVER_PORT=8081

CMD ["./http-header-security-scanner"]
