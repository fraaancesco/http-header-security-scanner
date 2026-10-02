package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fraaancesco/http-header-security-scanner/internal/config"

	"github.com/gin-gonic/gin"
)

func stubServer(t *testing.T, runErr error) (gotAddr *string, fatalCalled *bool) {
	t.Helper()
	origRun, origFatal := runServer, fatal
	t.Cleanup(func() { runServer, fatal = origRun, origFatal })

	gotAddr = new(string)
	fatalCalled = new(bool)
	runServer = func(r *gin.Engine, addr string) error {
		if r == nil {
			t.Fatal("router is nil")
		}
		*gotAddr = addr
		return runErr
	}
	fatal = func(v ...any) { *fatalCalled = true }
	return gotAddr, fatalCalled
}

func TestMainUsesConfiguredPort(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	t.Setenv("SERVER_PORT", "9999")
	addr, fatalCalled := stubServer(t, nil)

	main()

	if *addr != ":9999" {
		t.Errorf("addr = %q, want %q", *addr, ":9999")
	}
	if *fatalCalled {
		t.Error("fatal called on successful run")
	}
}

func TestMainCallsFatalOnRunError(t *testing.T) {
	t.Setenv("GIN_MODE", gin.TestMode)
	_, fatalCalled := stubServer(t, errors.New("boom"))

	main()

	if !*fatalCalled {
		t.Error("fatal not called on run error")
	}
}

func TestDefaultRunServerReturnsListenError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	if err := runServer(gin.New(), "invalid-address"); err == nil {
		t.Error("expected error for invalid address")
	}
}

func TestNewRouterRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := newRouter(config.Load())

	tests := []struct {
		name, method, path, body string
		want                     int
	}{
		{"scan rejects empty body", http.MethodPost, "/scan", "{}", http.StatusBadRequest},
		{"swagger served", http.MethodGet, "/swagger/doc.json", "", http.StatusOK},
		{"unknown route", http.MethodGet, "/nope", "", http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			r.ServeHTTP(w, req)
			if w.Code != tt.want {
				t.Errorf("status = %d, want %d", w.Code, tt.want)
			}
		})
	}
}
