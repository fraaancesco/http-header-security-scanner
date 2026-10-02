package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fraaancesco/http-header-security-scanner/pkg/models"
)

const testSpec = `{
  "openapi": "3.0.0",
  "servers": [{"url": "/api"}],
  "paths": {
    "/users/{id}": {"get": {}},
    "/secure": {"get": {}, "post": {}}
  }
}`

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

// newAPI serves testSpec at /openapi.json; /api/secure sends every security
// header, the other routes send none. It records the paths and tokens it saw.
func newAPI(t *testing.T) (srv *httptest.Server, seen *[]string) {
	t.Helper()
	seen = new([]string)
	var mu sync.Mutex
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi.json":
			w.Write([]byte(testSpec))
			return
		case "/api/secure":
			for _, h := range models.SecurityHeaders {
				w.Header().Set(h.Name, "x")
			}
		}
		mu.Lock()
		*seen = append(*seen, r.URL.Path+" "+r.Header.Get("Authorization"))
		mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	return srv, seen
}

func runCmd(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRunTextFromURL(t *testing.T) {
	srv, seen := newAPI(t)

	code, out, _ := runCmd("-spec", srv.URL+"/openapi.json", "-param", "id=42", "-token", "tok")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	for _, want := range []string{
		"2 endpoints from " + srv.URL + "/openapi.json, base " + srv.URL + "/api",
		"critical  0%",
		"/users/{id}",
		"ok        100%",
		"GET,POST  /secure",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	sort.Strings(*seen)
	got := strings.Join(*seen, ",")
	if got != "/api/secure Bearer tok,/api/users/42 Bearer tok" {
		t.Errorf("requests = %s", got)
	}
}

func TestRunMarkdownToFile(t *testing.T) {
	srv, _ := newAPI(t)
	specPath := filepath.Join(t.TempDir(), "openapi.json")
	os.WriteFile(specPath, []byte(testSpec), 0o600)
	outPath := filepath.Join(t.TempDir(), "report.md")

	origNow := now
	t.Cleanup(func() { now = origNow })
	now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }

	code, out, _ := runCmd("-spec", specPath, "-base", srv.URL, "-format", "markdown", "-out", outPath)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "Totals: error 0, critical 1") || !strings.Contains(out, "Report written to "+outPath) {
		t.Errorf("stdout = %s", out)
	}
	md, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# HTTP security headers report", "**Date:** 2026-01-02T03:04:05Z", "`/users/{id}`"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
}

func TestRunJSON(t *testing.T) {
	srv, _ := newAPI(t)
	code, out, _ := runCmd("-spec", srv.URL+"/openapi.json", "-format", "json")
	if code != 0 || !strings.Contains(out, `"class": "critical"`) {
		t.Errorf("code = %d, out = %s", code, out)
	}
}

func TestRunFailOn(t *testing.T) {
	srv, _ := newAPI(t)
	specURL := srv.URL + "/openapi.json"
	if code, _, _ := runCmd("-spec", specURL, "-fail-on", "critical"); code != 1 {
		t.Errorf("fail-on critical: exit code = %d, want 1", code)
	}
	if code, _, _ := runCmd("-spec", specURL, "-fail-on", "error"); code != 0 {
		t.Errorf("fail-on error: exit code = %d, want 0", code)
	}
}

func TestRunUsageErrors(t *testing.T) {
	tests := map[string][]string{
		"unknown flag":    {"-nope"},
		"bad param":       {"-spec", "s", "-param", "novalue"},
		"missing spec":    {},
		"bad format":      {"-spec", "s", "-format", "xml"},
		"bad fail-on":     {"-spec", "s", "-fail-on", "ok"},
		"bad timeout":     {"-spec", "s", "-timeout", "0"},
		"bad concurrency": {"-spec", "s", "-concurrency", "0"},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			if code, _, stderr := runCmd(args...); code != 2 || stderr == "" {
				t.Errorf("exit code = %d, stderr = %q; want 2 with message", code, stderr)
			}
		})
	}
}

func TestRunInputErrors(t *testing.T) {
	dir := t.TempDir()
	invalid := filepath.Join(dir, "invalid.json")
	os.WriteFile(invalid, []byte("{"), 0o600)
	relative := filepath.Join(dir, "relative.json")
	os.WriteFile(relative, []byte(testSpec), 0o600)

	tests := map[string][]string{
		"missing spec file": {"-spec", filepath.Join(dir, "missing.json")},
		"invalid spec":      {"-spec", invalid},
		"no base url":       {"-spec", relative},
		"bad output path":   {"-spec", relative, "-base", "http://127.0.0.1:1", "-out", filepath.Join(dir, "no", "such", "dir.md")},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			if code, _, stderr := runCmd(args...); code != 2 || !strings.HasPrefix(stderr, "hscan: ") {
				t.Errorf("exit code = %d, stderr = %q; want 2 with message", code, stderr)
			}
		})
	}
}

func TestRunWriteErrors(t *testing.T) {
	srv, _ := newAPI(t)
	specURL := srv.URL + "/openapi.json"
	outPath := filepath.Join(t.TempDir(), "report.md")

	for name, args := range map[string][]string{
		"stdout report":  {"-spec", specURL},
		"stdout summary": {"-spec", specURL, "-format", "markdown", "-out", outPath},
	} {
		t.Run(name, func(t *testing.T) {
			var errOut bytes.Buffer
			if code := run(args, failWriter{}, &errOut); code != 2 || !strings.Contains(errOut.String(), "write failed") {
				t.Errorf("exit code = %d, stderr = %q", code, errOut.String())
			}
		})
	}
}

func TestParamFlagString(t *testing.T) {
	if (paramFlag{"a": "b"}).String() != "" {
		t.Error("String() should be empty")
	}
}

func TestMainExitsWithRunCode(t *testing.T) {
	origExit, origArgs := exit, os.Args
	t.Cleanup(func() { exit, os.Args = origExit, origArgs })

	code := -1
	exit = func(c int) { code = c }
	os.Args = []string{"hscan"}

	main()

	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
}
