# HTTP Header Security Scanner

A Go tool that checks the HTTP security headers of web applications and APIs. It comes in three forms:

- **`hscan` CLI**: reads a project's Swagger/OpenAPI spec, scans every documented endpoint, classifies each one and writes a report (text, Markdown or JSON) explaining what every missing header exposes you to and how to fix it.
- **`header-scan` skill for Claude Code**: lets Claude find the spec, run `hscan` and summarize the result, instead of inspecting endpoints by hand (faster, and far fewer tokens).
- **REST API**: a `POST /scan` endpoint with Swagger UI, to scan arbitrary URLs.

> It checks HTTP security headers only. It is a quick first filter, not a complete security review: authentication, input validation, TLS configuration, CORS and rate limiting are out of scope.

## Contents

- [Security headers checked](#security-headers-checked)
- [Claude Code skill: installation guide](#claude-code-skill-installation-guide)
- [hscan CLI](#hscan-cli)
- [The report](#the-report)
- [REST API](#rest-api)
- [Configuration](#configuration)
- [Development and testing](#development-and-testing)
- [Project structure](#project-structure)

## Security headers checked

23 headers, each with a severity, the risk of leaving it out and a recommendation.

| Severity | Headers |
|----------|---------|
| **Critical** | Strict-Transport-Security, Content-Security-Policy |
| **High** | X-Frame-Options, X-Content-Type-Options, Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, Cross-Origin-Embedder-Policy |
| **Medium** | Referrer-Policy, Permissions-Policy, Cache-Control, Clear-Site-Data |
| **Low** | X-XSS-Protection, X-Permitted-Cross-Domain-Policies, X-DNS-Prefetch-Control, X-Download-Options, Expect-CT, X-Robots-Tag, Origin-Agent-Cluster, Timing-Allow-Origin, Content-Disposition, NEL, Report-To, Content-Security-Policy-Report-Only |

The full texts live in [`pkg/models/headers.go`](pkg/models/headers.go).

## Claude Code skill: installation guide

The `header-scan` skill turns "check the security headers of this API" into a single `hscan` run. Claude finds the project's Swagger/OpenAPI spec, runs the scan, writes `security-headers-report.md` and replies with a short summary. It does not read the spec or call the endpoints itself.

### 1. Prerequisites

- [Claude Code](https://code.claude.com) (CLI, desktop app, IDE extension or web).
- [Go](https://go.dev/dl/) 1.25 or later, used to install `hscan`.
- A project with a Swagger 2.0 or OpenAPI 3 spec, either as a file (`swagger.json`, `openapi.yaml`, ...) or served by the running app (`/v3/api-docs`, `/swagger/doc.json`, `/openapi.json`, ...).

### 2. Install the `hscan` CLI

```bash
go install github.com/fraaancesco/http-header-security-scanner/cmd/hscan@latest
```

The binary goes to `$(go env GOPATH)/bin` (usually `~/go/bin`). Make sure that directory is in your `PATH`:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"   # add it to ~/.bashrc or ~/.zshrc
hscan -h                                  # check that it works
```

You can skip this step: the skill installs `hscan` the first time it runs if it is missing.

### 3. Install the skill

Choose where it should be available.

**For every project (user level):**

```bash
mkdir -p ~/.claude/skills/header-scan
curl -fsSL https://raw.githubusercontent.com/fraaancesco/http-header-security-scanner/main/.claude/skills/header-scan/SKILL.md \
  -o ~/.claude/skills/header-scan/SKILL.md
```

**For one project only (shared with the team through git):**

```bash
cd /path/to/your-project
mkdir -p .claude/skills/header-scan
curl -fsSL https://raw.githubusercontent.com/fraaancesco/http-header-security-scanner/main/.claude/skills/header-scan/SKILL.md \
  -o .claude/skills/header-scan/SKILL.md
git add .claude/skills/header-scan && git commit -m "Add header-scan skill"
```

**From a clone of this repository:**

```bash
git clone https://github.com/fraaancesco/http-header-security-scanner.git
cd http-header-security-scanner
make install-hscan   # installs hscan
make install-skill   # copies the skill to ~/.claude/skills/
```

### 4. Check the installation

Start a new Claude Code session in your project (skills are loaded at startup) and type `/header-scan`, or ask "which skills are available?". `header-scan` should be listed.

### 5. Use it

Start your app, then ask Claude, for example:

- "Scan the security headers of the API"
- "/header-scan against http://localhost:3000"
- "Check the headers of the endpoints in openapi.yaml, the user id to use is 42"

Claude will:

1. find the spec (asking you if there are several);
2. choose the base URL. It asks before starting the app or scanning a host you have not approved, and never picks a production URL on its own;
3. run `hscan ... -format markdown -out security-headers-report.md`;
4. reply with the totals per class, the critical and high headers missing everywhere (with their risk and where the project sets response headers), the endpoints that miss more than the others, and the errors.

For authenticated APIs, export the token before starting Claude Code, so it never ends up in the conversation or in the report:

```bash
export HSCAN_TOKEN="eyJhbGciOi..."
```

### 6. Update or uninstall

Update by running the install commands again (`go install ...@latest` and the `curl` command). Uninstall with:

```bash
rm -rf ~/.claude/skills/header-scan          # or .claude/skills/header-scan in the project
rm -f "$(go env GOPATH)/bin/hscan"
```

### Troubleshooting

| Problem | Fix |
|---------|-----|
| `hscan: command not found` | Add `$(go env GOPATH)/bin` to `PATH` (step 2). |
| `/header-scan` is not listed | Check the path `~/.claude/skills/header-scan/SKILL.md` and start a new session. |
| `declares no absolute server URL ... pass -base` | The spec has no absolute server: pass `-base http://localhost:<port>`. |
| All endpoints are `error` | The app is not running, or the base URL or port is wrong. |
| Many `404` statuses | Path parameters such as `{id}` default to `1`: pass a real value with `-param id=42`. |
| `401`/`403` statuses | Set `HSCAN_TOKEN` with a valid bearer token. |
| `x509: certificate` errors | Self-signed certificate in a local or test environment: add `-insecure`. |

## hscan CLI

`hscan` reads a Swagger 2.0 or OpenAPI 3 document (JSON or YAML, file or URL), sends a GET request to every documented path and classifies each endpoint by the most severe header it is missing.

```bash
# Compact summary on stdout
hscan -spec docs/swagger.json -base http://localhost:8081

# Markdown report (a text summary still goes to stdout)
hscan -spec http://localhost:8080/v3/api-docs -format markdown -out security-headers-report.md

# CI: exit code 1 if any endpoint is high or worse
hscan -spec openapi.yaml -fail-on high
```

| Flag | Default | Description |
|------|---------|-------------|
| `-spec` | (required) | Spec file path or http(s) URL |
| `-base` | server declared in the spec | Base URL. It replaces scheme and host and keeps the spec's base path, unless it has a path of its own |
| `-param name=value` | `1` | Value for a path parameter; repeatable |
| `-token` | `$HSCAN_TOKEN` | Bearer token sent to every endpoint |
| `-format` | `text` | `text`, `markdown` or `json` |
| `-out` | stdout | Write the report to a file |
| `-fail-on` | `none` | Exit 1 if an endpoint is classified at or above `error`, `critical`, `high`, `medium` or `low` |
| `-timeout` | `10` | Per-request timeout in seconds |
| `-concurrency` | `8` | Parallel requests |
| `-insecure` | `false` | Skip TLS certificate verification |

Only GET requests are sent, without a body, so documented POST, PUT and DELETE routes are never triggered. They may answer 405, but their headers are still checked.

Exit codes: `0` success, `1` the `-fail-on` threshold was reached, `2` invalid input (missing spec, unreachable spec URL, invalid document, no base URL).

### Classes

| Class | Meaning |
|-------|---------|
| `error` | Could not be reached, so it was not checked |
| `critical` | Exposed to direct attacks such as HTTPS downgrade and unrestricted script injection |
| `high` | Exposed to clickjacking, MIME sniffing or cross-origin attacks |
| `medium` | Exposed to data leaks through referrers, caches or browser features |
| `low` | Only legacy-browser hardening or monitoring headers are missing |
| `ok` | Every checked header is present |

## The report

With `-format markdown`, the report contains:

1. **Totals**: endpoints per class, with the meaning of each class.
2. **Endpoints**: class, score, HTTP status, documented methods and path of every endpoint, worst first.
3. **Missing on every reachable endpoint**: usually fixed once, in a shared middleware or in the reverse proxy.
4. **Also missing on single endpoints**: the differences from the common set.
5. **Risks and recommendations**: for every missing header, what it exposes you to, how to fix it and where it is missing.
6. **Errors**: endpoints that could not be reached, with the reason.

Excerpt:

```markdown
### `Strict-Transport-Security` (critical)

- **Risk:** Browsers may reach the site over plain HTTP first, so an attacker on the network (public Wi-Fi, compromised router) can downgrade the connection with SSL stripping and read or modify the traffic, including session cookies and credentials.
- **Recommendation:** Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to enforce HTTPS connections and prevent man-in-the-middle attacks.
- **Missing on:** all reachable endpoints
```

`-format json` contains the full data, including the value, risk and recommendation of every header.

## REST API

### Run the server

```bash
# Docker
docker-compose up -d

# Make (generates Swagger, builds and runs)
make install-tools
make run

# Manual
swag init -g cmd/server/main.go -o docs
go build -o http-header-security-scanner ./cmd/server
./http-header-security-scanner
```

### Endpoint

```
POST /scan
```

### Request body

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
| `timeout` | int | No | Request timeout in seconds (default: `SCANNER_TIMEOUT`) |
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
          "value": null,
          "severity": "critical",
          "risk": "There is no second line of defence against cross-site scripting...",
          "recommendation": "Add Content-Security-Policy header..."
        }
      ],
      "summary": {
        "total_checks": 23,
        "passed": 8,
        "failed": 15,
        "score": "35%"
      }
    }
  ]
}
```

### Swagger UI

```
http://localhost:8081/swagger/index.html
```

## Configuration

Environment variables of the REST API server:

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_PORT` | 8081 | Server port |
| `GIN_MODE` | debug | Gin mode (debug/release) |
| `SCANNER_TIMEOUT` | 10 | Default scan timeout in seconds |
| `SCANNER_INSECURE` | false | Default TLS verification setting |

`hscan` reads `HSCAN_TOKEN` as the default bearer token.

## Development and testing

```bash
make test           # run all tests
make coverage       # run tests with coverage; fails below 100%
make swagger        # regenerate docs/ after changing API models or annotations
make install-hscan  # install hscan from the working tree
make install-skill  # copy the skill to ~/.claude/skills/
```

Test coverage is 100% and is enforced by `make coverage`.

## Project structure

```
├── cmd/
│   ├── server/          # REST API entry point
│   └── hscan/           # CLI: scan every endpoint of a Swagger/OpenAPI spec
├── internal/
│   ├── config/          # Configuration management
│   ├── handler/         # HTTP handlers
│   ├── report/          # Endpoint classification and text/Markdown/JSON reports
│   ├── scanner/         # Scanning logic
│   └── spec/            # Swagger/OpenAPI parsing
├── pkg/models/          # Headers (severity, risk, recommendation) and shared models
├── docs/                # Swagger documentation (generated)
├── .claude/skills/
│   └── header-scan/     # Claude Code skill
├── Dockerfile
├── docker-compose.yml
└── Makefile
```
