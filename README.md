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

## Scan a whole API from its Swagger/OpenAPI spec (`hscan`)

`hscan` reads a Swagger 2.0 or OpenAPI 3 document (JSON or YAML, file or URL), calls every documented path and classifies each endpoint by the worst severity among its missing headers: `error`, `critical`, `high`, `medium`, `low` or `ok`.

```bash
go install github.com/fraaancesco/http-header-security-scanner/cmd/hscan@latest

# Compact summary on stdout
hscan -spec docs/swagger.json -base http://localhost:8081

# Markdown report (the summary still goes to stdout)
hscan -spec http://localhost:8080/v3/api-docs -format markdown -out security-headers-report.md

# CI: exit 1 if any endpoint is high or worse
hscan -spec openapi.yaml -fail-on high
```

| Flag | Default | Description |
|------|---------|-------------|
| `-spec` | (required) | Spec file path or http(s) URL |
| `-base` | server in the spec | Base URL; replaces scheme and host, keeps the spec's base path unless it has its own |
| `-param name=value` | `1` | Value for a path parameter, repeatable |
| `-token` | `$HSCAN_TOKEN` | Bearer token sent to every endpoint |
| `-format` | `text` | `text`, `markdown` or `json` |
| `-out` | stdout | Write the report to a file |
| `-fail-on` | `none` | Exit 1 if an endpoint is at or above this class |
| `-timeout` / `-concurrency` / `-insecure` | `10` / `8` / `false` | Per-request timeout (s), parallel requests, skip TLS verification |

Only GET requests are sent, without a body, so documented POST/PUT/DELETE routes are never triggered (they may answer 405, but their headers are still checked). Exit codes: `0` ok, `1` `-fail-on` threshold reached, `2` invalid input.

### Claude Code skill

`.claude/skills/header-scan/SKILL.md` makes Claude find the project's spec, run `hscan` once and summarize the result, instead of inspecting every endpoint by hand. To use it in another project, copy the folder:

```bash
# for one project
cp -r .claude/skills/header-scan <project>/.claude/skills/
# for every project
cp -r .claude/skills/header-scan ~/.claude/skills/
```

Then ask Claude something like "scan the API security headers" or run `/header-scan`.

## Testing

```bash
# Run all tests
make test

# Run tests with coverage (fails if total coverage is below 100%)
make coverage
```

## Project Structure

```
├── cmd/server/          # API server entry point
├── cmd/hscan/           # CLI: scan every endpoint of a Swagger/OpenAPI spec
├── internal/
│   ├── config/          # Configuration management
│   ├── handler/         # HTTP handlers
│   ├── report/          # Endpoint classification and text/Markdown/JSON reports
│   ├── scanner/         # Scanning logic
│   └── spec/            # Swagger/OpenAPI parsing
├── pkg/models/          # Shared models
├── docs/                # Swagger documentation (generated)
├── .claude/skills/      # Claude Code skill (header-scan)
├── Dockerfile
├── docker-compose.yml
└── Makefile
```
