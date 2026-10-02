package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fraaancesco/http-header-security-scanner/pkg/models"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if opts.Timeout != 10*time.Second || opts.Insecure || opts.BearerToken != "" {
		t.Errorf("DefaultOptions() = %+v", opts)
	}
}

func TestScanAllHeadersPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range models.SecurityHeaders {
			w.Header().Set(h.Name, "x")
		}
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	res := Scan(srv.URL, DefaultOptions())

	if res.Error != nil {
		t.Fatalf("unexpected error: %s", *res.Error)
	}
	if res.URL != srv.URL || res.StatusCode != http.StatusTeapot {
		t.Errorf("URL/StatusCode = %q/%d", res.URL, res.StatusCode)
	}
	for _, h := range res.Headers {
		if !h.Present || h.Value == nil || *h.Value != "x" || h.Severity != models.SeverityOK || h.Recommendation != nil {
			t.Errorf("header %q not reported as present: %+v", h.Name, h)
		}
	}
	want := models.Summary{TotalChecks: len(models.SecurityHeaders), Passed: len(models.SecurityHeaders), Score: "100%"}
	if *res.Summary != want {
		t.Errorf("Summary = %+v, want %+v", *res.Summary, want)
	}
}

func TestScanMissingHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=1")
	}))
	defer srv.Close()

	res := Scan(srv.URL, DefaultOptions())

	if len(res.Headers) != len(models.SecurityHeaders) {
		t.Fatalf("got %d headers, want %d", len(res.Headers), len(models.SecurityHeaders))
	}
	for i, h := range res.Headers {
		def := models.SecurityHeaders[i]
		if h.Name != def.Name {
			t.Errorf("header %d = %q, want %q", i, h.Name, def.Name)
		}
		if h.Name == "Strict-Transport-Security" {
			if !h.Present {
				t.Error("HSTS should be present")
			}
			continue
		}
		if h.Present || h.Value != nil || h.Severity != def.Severity || h.Recommendation == nil || *h.Recommendation != def.Recommendation {
			t.Errorf("header %q not reported as missing: %+v", h.Name, h)
		}
	}
	total := len(models.SecurityHeaders)
	if res.Summary.Passed != 1 || res.Summary.Failed != total-1 || res.Summary.TotalChecks != total {
		t.Errorf("Summary = %+v", *res.Summary)
	}
	if !strings.HasSuffix(res.Summary.Score, "%") {
		t.Errorf("Score = %q, want percentage", res.Summary.Score)
	}
}

func TestScanSendsBearerToken(t *testing.T) {
	tests := []struct{ token, want string }{
		{"secret", "Bearer secret"},
		{"", ""},
	}
	for _, tt := range tests {
		var got string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.Header.Get("Authorization")
		}))
		opts := DefaultOptions()
		opts.BearerToken = tt.token
		Scan(srv.URL, opts)
		srv.Close()
		if got != tt.want {
			t.Errorf("token %q: Authorization = %q, want %q", tt.token, got, tt.want)
		}
	}
}

func TestScanInvalidURL(t *testing.T) {
	res := Scan("://bad", DefaultOptions())
	if res.Error == nil {
		t.Fatal("expected error for invalid URL")
	}
	if res.Headers != nil || res.Summary != nil {
		t.Error("headers/summary should be empty on error")
	}
}

func TestScanConnectionError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	res := Scan(url, DefaultOptions())
	if res.Error == nil {
		t.Fatal("expected connection error")
	}
	if res.StatusCode != 0 {
		t.Errorf("StatusCode = %d, want 0", res.StatusCode)
	}
}

func TestScanTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	opts := DefaultOptions()
	if res := Scan(srv.URL, opts); res.Error == nil {
		t.Error("expected certificate error without Insecure")
	}

	opts.Insecure = true
	if res := Scan(srv.URL, opts); res.Error != nil {
		t.Errorf("unexpected error with Insecure: %s", *res.Error)
	}
}

func TestScanTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()

	opts := DefaultOptions()
	opts.Timeout = 20 * time.Millisecond
	if res := Scan(srv.URL, opts); res.Error == nil {
		t.Error("expected timeout error")
	}
}
