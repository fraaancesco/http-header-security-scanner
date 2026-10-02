package spec

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const swaggerJSON = `{
  "swagger": "2.0",
  "host": "localhost:8081",
  "basePath": "/api",
  "paths": {
    "/users/{id}": {"get": {}, "delete": {}, "parameters": []},
    "/scan": {"post": {}}
  }
}`

const openapiYAML = `openapi: 3.0.0
servers:
  - url: https://api.example.com/v1
paths:
  /health:
    get: {}
`

func TestLoadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "swagger.json")
	if err := os.WriteFile(path, []byte(swaggerJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := Load(path, http.DefaultClient)
	if err != nil || string(data) != swaggerJSON {
		t.Fatalf("Load() = %q, %v", data, err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json"), http.DefaultClient); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Write([]byte(openapiYAML))
		case "/short":
			w.Header().Set("Content-Length", "100")
			w.Write([]byte("short"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	data, err := Load(srv.URL+"/ok", srv.Client())
	if err != nil || string(data) != openapiYAML {
		t.Fatalf("Load() = %q, %v", data, err)
	}
	if _, err := Load(srv.URL+"/missing", srv.Client()); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("expected status error, got %v", err)
	}
	if _, err := Load(srv.URL+"/short", srv.Client()); err == nil {
		t.Error("expected error for truncated body")
	}

	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	if _, err := Load(closed.URL, http.DefaultClient); err == nil {
		t.Error("expected connection error")
	}
}

func TestParseSwagger(t *testing.T) {
	s, err := Parse([]byte("  " + swaggerJSON))
	if err != nil {
		t.Fatal(err)
	}
	want := &Spec{
		ServerURL: "http://localhost:8081/api",
		Paths: []Path{
			{Template: "/scan", Methods: []string{"POST"}},
			{Template: "/users/{id}", Methods: []string{"DELETE", "GET"}},
		},
	}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("Parse() = %+v, want %+v", s, want)
	}
}

func TestParseOpenAPIYAML(t *testing.T) {
	s, err := Parse([]byte(openapiYAML))
	if err != nil {
		t.Fatal(err)
	}
	if s.ServerURL != "https://api.example.com/v1" || len(s.Paths) != 1 || s.Paths[0].Methods[0] != "GET" {
		t.Errorf("Parse() = %+v", s)
	}
}

func TestParseErrors(t *testing.T) {
	tests := map[string]string{
		"invalid json":   `{"swagger":`,
		"invalid yaml":   "openapi: [",
		"not a spec":     `{"paths": {"/a": {"get": {}}}}`,
		"no paths":       `{"openapi": "3.0.0"}`,
		"empty document": "",
	}
	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestServerURL(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{"openapi without servers", `{"openapi":"3.0.0","paths":{"/a":{}}}`, ""},
		{"swagger without host", `{"swagger":"2.0","basePath":"/v2","paths":{"/a":{}}}`, "/v2"},
		{"swagger declared scheme", `{"swagger":"2.0","host":"localhost","schemes":["https"],"paths":{"/a":{}}}`, "https://localhost"},
		{"swagger remote host", `{"swagger":"2.0","host":"api.example.com","paths":{"/a":{}}}`, "https://api.example.com"},
		{"swagger loopback host", `{"swagger":"2.0","host":"127.0.0.1:9000","paths":{"/a":{}}}`, "http://127.0.0.1:9000"},
		{"swagger any address", `{"swagger":"2.0","host":"0.0.0.0","paths":{"/a":{}}}`, "http://0.0.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Parse([]byte(tt.doc))
			if err != nil {
				t.Fatal(err)
			}
			if s.ServerURL != tt.want {
				t.Errorf("ServerURL = %q, want %q", s.ServerURL, tt.want)
			}
		})
	}
}

func TestResolveBase(t *testing.T) {
	tests := []struct {
		name, override, server, source, want string
	}{
		{"absolute server", "", "https://api.example.com/v1/", "spec.yaml", "https://api.example.com/v1"},
		{"override keeps server path", "http://localhost:3000/", "https://api.example.com/v1", "spec.yaml", "http://localhost:3000/v1"},
		{"override with path", "http://localhost:3000/api", "https://api.example.com/v1", "spec.yaml", "http://localhost:3000/api"},
		{"relative server from url", "", "/api", "http://localhost:8080/docs/openapi.json", "http://localhost:8080/api"},
		{"no server from url", "", "", "http://localhost:8080/docs/openapi.json", "http://localhost:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveBase(tt.override, tt.server, tt.source)
			if err != nil || got != tt.want {
				t.Errorf("ResolveBase() = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestResolveBaseErrors(t *testing.T) {
	tests := []struct {
		name, override, server, source string
	}{
		{"invalid server", "", "http://[::1", "spec.yaml"},
		{"override not absolute", "localhost:3000", "", "spec.yaml"},
		{"override unparsable", "http://%zz", "", "spec.yaml"},
		{"invalid source", "", "/api", "http://%zz"},
		{"relative server from file", "", "/api", "spec.yaml"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := ResolveBase(tt.override, tt.server, tt.source); err == nil {
				t.Errorf("expected error, got %q", got)
			}
		})
	}
}

func TestEndpoints(t *testing.T) {
	s := &Spec{Paths: []Path{
		{Template: "/users/{id}/posts/{postId}", Methods: []string{"GET"}},
		{Template: "health", Methods: []string{"GET"}},
	}}
	got := Endpoints(s, "http://localhost:8080/api", map[string]string{"id": "a b"})
	want := []Endpoint{
		{Path: "/users/{id}/posts/{postId}", Methods: []string{"GET"}, URL: "http://localhost:8080/api/users/a%20b/posts/1"},
		{Path: "health", Methods: []string{"GET"}, URL: "http://localhost:8080/api/health"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Endpoints() = %+v, want %+v", got, want)
	}
}
