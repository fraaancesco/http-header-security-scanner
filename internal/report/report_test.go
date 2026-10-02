package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/fraaancesco/http-header-security-scanner/internal/spec"
	"github.com/fraaancesco/http-header-security-scanner/pkg/models"
)

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

// result builds a scan result where every header is present except missing.
func result(missing ...string) models.ScanResult {
	skip := map[string]bool{}
	for _, m := range missing {
		skip[m] = true
	}
	var headers []models.HeaderResult
	passed := 0
	for _, h := range models.SecurityHeaders {
		hr := models.HeaderResult{Name: h.Name, Present: !skip[h.Name], Severity: models.SeverityOK}
		if skip[h.Name] {
			hr.Severity = h.Severity
		} else {
			passed++
		}
		headers = append(headers, hr)
	}
	return models.ScanResult{
		StatusCode: 200,
		Headers:    headers,
		Summary:    &models.Summary{Passed: passed, Score: "x%"},
	}
}

func errResult(msg string) models.ScanResult {
	return models.ScanResult{Error: &msg}
}

func endpoint(path string) spec.Endpoint {
	return spec.Endpoint{Path: path, Methods: []string{"GET", "POST"}, URL: "http://x" + path}
}

func TestRank(t *testing.T) {
	if Rank(SeverityError) <= Rank(models.SeverityCritical) || Rank(models.SeverityOK) != 0 {
		t.Error("unexpected rank order")
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		r    models.ScanResult
		want models.Severity
	}{
		{"error", errResult("boom"), SeverityError},
		{"all present", result(), models.SeverityOK},
		{"low only", result("NEL"), models.SeverityLow},
		{"worst wins", result("NEL", "X-Frame-Options", "Referrer-Policy"), models.SeverityHigh},
		{"critical", result("Content-Security-Policy", "NEL"), models.SeverityCritical},
	}
	for _, tt := range tests {
		if got := Classify(tt.r); got != tt.want {
			t.Errorf("%s: Classify() = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func sample() *Report {
	return New("spec.json", "http://x",
		[]spec.Endpoint{endpoint("/b"), endpoint("/ok"), endpoint("/a"), endpoint("/down")},
		[]models.ScanResult{
			result("Content-Security-Policy", "NEL", "Referrer-Policy"),
			result("Content-Security-Policy", "NEL"),
			result("Content-Security-Policy", "NEL", "X-Frame-Options", "Referrer-Policy"),
			errResult("connection refused"),
		})
}

func TestNewSortsAndCounts(t *testing.T) {
	r := sample()
	var order []string
	for _, e := range r.Entries {
		order = append(order, e.Path+":"+string(e.Class))
	}
	if got := strings.Join(order, " "); got != "/down:error /a:critical /b:critical /ok:critical" {
		t.Errorf("order = %s", got)
	}
	if r.Counts[SeverityError] != 1 || r.Counts[models.SeverityCritical] != 3 || r.Counts[models.SeverityOK] != 0 {
		t.Errorf("Counts = %v", r.Counts)
	}
}

func TestFails(t *testing.T) {
	r := New("s", "b", []spec.Endpoint{endpoint("/a")}, []models.ScanResult{result("Referrer-Policy")})
	if !r.Fails(models.SeverityMedium) || !r.Fails(models.SeverityLow) {
		t.Error("expected failure at or below medium")
	}
	if r.Fails(models.SeverityHigh) {
		t.Error("unexpected failure at high")
	}
}

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	if err := sample().WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"4 endpoints from spec.json, base http://x",
		"error     -      -       GET,POST  /down",
		"critical  x%     200     GET,POST  /a",
		"Missing on every reachable endpoint",
		"critical  Content-Security-Policy",
		"low       1 headers",
		"Also missing on single endpoints:",
		"/a  high: X-Frame-Options; medium: Referrer-Policy",
		"/b  medium: Referrer-Policy",
		"Errors:\n  /down  connection refused",
		"Totals: error 1, critical 3, high 0, medium 0, low 0, ok 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\n  medium") {
		t.Errorf("medium should not be common:\n%s", out)
	}
}

func TestWriteTextNothingCommon(t *testing.T) {
	r := New("s", "b",
		[]spec.Endpoint{endpoint("/ok"), endpoint("/down")},
		[]models.ScanResult{result(), errResult("boom")})
	var buf bytes.Buffer
	if err := r.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"Missing on every", "Also missing"} {
		if strings.Contains(buf.String(), unwanted) {
			t.Errorf("unexpected %q:\n%s", unwanted, buf.String())
		}
	}
}

func TestWriteMarkdown(t *testing.T) {
	r := sample()
	r.ScanDate = "2026-01-01T00:00:00Z"
	var buf bytes.Buffer
	if err := r.WriteMarkdown(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"# HTTP security headers report",
		"- **Date:** 2026-01-01T00:00:00Z",
		"- **Endpoints:** 4",
		"| error | 1 | Could not be reached",
		"| critical | 3 | Exposed to direct attacks",
		"| critical | x% | 200 | GET, POST | `/a` |",
		"| error | - | - | GET, POST | `/down` |",
		"| critical | `Content-Security-Policy` |",
		"| low | `NEL` |",
		"- `/a`: high: X-Frame-Options; medium: Referrer-Policy",
		"## Risks and recommendations",
		"### `Content-Security-Policy` (critical)\n\n- **Risk:** There is no second line of defence",
		"- **Recommendation:** Add Content-Security-Policy",
		"- **Missing on:** all reachable endpoints",
		"### `Referrer-Policy` (medium)",
		"- **Missing on:** `/a`, `/b`",
		"## Errors\n\n- `/down`: connection refused",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q:\n%s", want, out)
		}
	}
}

func TestWriteMarkdownMinimal(t *testing.T) {
	r := New("s", "b", []spec.Endpoint{endpoint("/ok")}, []models.ScanResult{result()})
	var buf bytes.Buffer
	if err := r.WriteMarkdown(&buf); err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"**Date:**", "## Missing", "## Also", "## Risks", "## Errors"} {
		if strings.Contains(buf.String(), unwanted) {
			t.Errorf("unexpected %q:\n%s", unwanted, buf.String())
		}
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := sample().WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Counts    map[string]int `json:"counts"`
		Endpoints []struct {
			Path  string `json:"path"`
			URL   string `json:"url"`
			Class string `json:"class"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Counts["critical"] != 3 || got.Endpoints[0].Path != "/down" || got.Endpoints[0].URL != "http://x/down" || got.Endpoints[0].Class != "error" {
		t.Errorf("unexpected JSON: %s", buf.String())
	}
}

func TestWriteErrors(t *testing.T) {
	r := sample()
	for name, write := range map[string]func(w failWriter) error{
		"text":     func(w failWriter) error { return r.WriteText(w) },
		"markdown": func(w failWriter) error { return r.WriteMarkdown(w) },
		"json":     func(w failWriter) error { return r.WriteJSON(w) },
	} {
		if err := write(failWriter{}); err == nil {
			t.Errorf("%s: expected write error", name)
		}
	}
}
