package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fraaancesco/http-header-security-scanner/pkg/models"

	"github.com/gin-gonic/gin"
)

func performScan(t *testing.T, h *ScanHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/scan", h.Scan)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	return w
}

func scanOne(t *testing.T, h *ScanHandler, body string) models.ScanResult {
	t.Helper()
	w := performScan(t, h, body)
	var report models.Report
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 {
		t.Fatalf("got %d results, want 1", len(report.Results))
	}
	return report.Results[0]
}

func TestScanBadRequest(t *testing.T) {
	tests := map[string]string{
		"invalid json": "{",
		"missing urls": "{}",
		"empty urls":   `{"urls":[]}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			w := performScan(t, NewScanHandler(time.Second), body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", w.Code)
			}
			var resp ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Error == "" {
				t.Errorf("bad error body %q (%v)", w.Body.String(), err)
			}
		})
	}
}

func TestScanSuccess(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.Header().Set("X-Frame-Options", "DENY")
	}))
	defer srv.Close()

	body := `{"urls":["` + srv.URL + `","://bad"],"bearer_token":"tok"}`
	w := performScan(t, NewScanHandler(time.Second), body)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var report models.Report
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if _, err := time.Parse(time.RFC3339, report.ScanDate); err != nil {
		t.Errorf("ScanDate %q not RFC3339: %v", report.ScanDate, err)
	}
	if len(report.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(report.Results))
	}
	if r := report.Results[0]; r.URL != srv.URL || r.StatusCode != http.StatusOK || r.Error != nil || r.Summary.Passed != 1 {
		t.Errorf("first result = %+v", r)
	}
	if r := report.Results[1]; r.URL != "://bad" || r.Error == nil {
		t.Errorf("second result = %+v", r)
	}
	if auth != "Bearer tok" {
		t.Errorf("Authorization = %q, want %q", auth, "Bearer tok")
	}
}

func TestScanTimeoutOverride(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
	}))
	defer srv.Close()

	// A tiny default timeout fails; the per-request timeout (1s) overrides it.
	h := NewScanHandler(10 * time.Millisecond)

	if res := scanOne(t, h, `{"urls":["`+srv.URL+`"]}`); res.Error == nil {
		t.Error("expected default timeout to fail")
	}
	if res := scanOne(t, h, `{"urls":["`+srv.URL+`"],"timeout":1}`); res.Error != nil {
		t.Errorf("unexpected error with timeout override: %s", *res.Error)
	}
}
