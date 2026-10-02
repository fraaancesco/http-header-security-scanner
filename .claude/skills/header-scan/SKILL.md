---
name: header-scan
description: Scan every endpoint documented in the project's Swagger/OpenAPI spec for missing HTTP security headers, classify each endpoint (error/critical/high/medium/low/ok) and write a Markdown report. Use when asked to check security headers, scan or classify the API endpoints, or for a quick header hardening check, instead of inspecting endpoints by hand.
---

# Security headers scan from the Swagger/OpenAPI spec

The `hscan` tool does the work: it reads the spec, calls every documented path and classifies it. Your job is only to find the inputs, run it once and summarize its output. Do not read the spec or call the endpoints yourself: that is what this skill saves.

## 1. Make sure `hscan` is installed

```bash
command -v hscan || go install github.com/fraaancesco/http-header-security-scanner/cmd/hscan@latest
```

It needs Go 1.27+ (Go 1.21+ downloads that toolchain automatically); the binary lands in `$(go env GOPATH)/bin`. If Go is missing, tell the user and stop.

## 2. Find the spec

Look for the file, skipping `node_modules`, `vendor`, `dist` and `build`:

```bash
find . \( -name node_modules -o -name vendor -o -name dist -o -name build -o -name .git \) -prune -o \
  -type f \( -iname 'swagger*.json' -o -iname 'swagger*.y*ml' -o -iname 'openapi*.json' -o -iname 'openapi*.y*ml' \) -print
```

If nothing is found but the app runs and generates the spec at runtime, pass its URL instead. Common ones: `/swagger/doc.json` (Go swag), `/v3/api-docs` (Spring), `/openapi.json` (FastAPI), `/swagger/v1/swagger.json` (ASP.NET), `/api-docs` (Express). If several specs exist, ask which one.

## 3. Pick the base URL

- By default `hscan` uses the server declared in the spec (`host`/`basePath` or `servers[0]`).
- To scan a local instance, pass `-base http://localhost:<port>`: it replaces scheme and host and keeps the spec's base path.
- The app must be running. If it is not, ask the user whether to start it, using the command in the project's README/Makefile/package.json, or for the URL of an environment to scan.
- Only scan hosts the user owns or has approved; never pick a production URL on your own.

## 4. Run it once

```bash
hscan -spec <file-or-url> [-base <url>] [-param id=<real id>] -format markdown -out security-headers-report.md
```

- Path parameters such as `{id}` default to `1`; pass `-param name=value` with real values when the summary shows 404s.
- Authenticated APIs: put the token in `HSCAN_TOKEN` (never on the command line or in the report).
- Only GET requests are sent, with no body, so POST/DELETE routes are never triggered. They often answer 405, but their headers are still checked.
- Exit code 2 means bad input (the message says what); `-fail-on <class>` makes it exit 1 for CI.

## 5. Report back

Use only the summary printed on stdout; do not open the Markdown file unless the user asks. Reply with:

1. the totals per class and the path of `security-headers-report.md`;
2. the critical/high headers missing on every endpoint, each with one short line on what it exposes the site to (the report has the full risk and recommendation): they are usually fixed once, so find where the project sets response headers (middleware, reverse proxy config) and point to it;
3. the endpoints that miss more than the others;
4. the errors, with the likely cause (app not running, wrong base URL, placeholder parameter).

This covers HTTP security headers only: say so, and do not present it as a complete hardening review.
