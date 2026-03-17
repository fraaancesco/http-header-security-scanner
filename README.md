# HTTP Header Security Scanner

A Go-based API tool that scans URLs and analyzes HTTP security headers configuration.

## Features

- Scans multiple URLs in a single request
- Checks 24 security headers with severity levels (Critical, High, Medium, Low)
- Provides recommendations for missing headers
- Supports Bearer token authentication for protected endpoints
- Swagger UI documentation
- Docker support

## Security Headers Checked

| Severity | Headers |
|----------|---------|
| **Critical** | Strict-Transport-Security, Content-Security-Policy |
| **High** | X-Frame-Options, X-Content-Type-Options, COOP, CORP, COEP |
| **Medium** | Referrer-Policy, Permissions-Policy, Cache-Control, Clear-Site-Data |
| **Low** | X-XSS-Protection, X-Permitted-Cross-Domain-Policies, X-DNS-Prefetch-Control, and more |

## Quick Start

### Using Docker (Recommended)

```bash
docker-compose up -d
```

### Using Make

```bash
# Install dependencies
make install-tools

# Build (generates Swagger + compiles)
make build

# Run
make run
```

### Manual Build

```bash
# Generate Swagger docs
swag init -g cmd/server/main.go -o docs

# Build
go build -o http-header-security-scanner ./cmd/server

# Run
./http-header-security-scanner
```

## API Usage

### Endpoint

```
POST /scan
```

### Request Body

```json
{
  "urls": ["https://example.com", "https://api.example.com"],
  "timeout": 10,
  "insecure": false,
  "bearer_token": "optional-jwt-token"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `urls` | array | Yes | List of URLs to scan |
| `timeout` | int | No | Request timeout in seconds (default: 10) |
| `insecure` | bool | No | Skip TLS verification (default: false) |
| `bearer_token` | string | No | Bearer token for authenticated endpoints |

### Response

```json
{
  "scan_date": "2026-01-10T17:30:00Z",
  "results": [
    {
      "url": "https://example.com",
      "status_code": 200,
      "headers": [
        {
          "name": "Strict-Transport-Security",
          "present": true,
          "value": "max-age=31536000; includeSubDomains",
          "severity": "ok"
        },
        {
          "name": "Content-Security-Policy",
          "present": false,
          "severity": "critical",
          "recommendation": "Add Content-Security-Policy header..."
        }
      ],
      "summary": {
        "total_checks": 24,
        "passed": 8,
        "failed": 16,
        "score": "33%"
      }
    }
  ]
}
```

## Swagger UI

Access the interactive API documentation at:

```
http://localhost:8081/swagger/index.html
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_PORT` | 8081 | Server port |
| `GIN_MODE` | debug | Gin mode (debug/release) |
| `SCANNER_TIMEOUT` | 10 | Default scan timeout in seconds |
| `SCANNER_INSECURE` | false | Default TLS verification setting |

## Project Structure

```
├── cmd/server/          # Application entry point
├── internal/
│   ├── config/          # Configuration management
│   ├── handler/         # HTTP handlers
│   └── scanner/         # Scanning logic
├── pkg/models/          # Shared models
├── docs/                # Swagger documentation (generated)
├── Dockerfile
├── docker-compose.yml
└── Makefile
```
