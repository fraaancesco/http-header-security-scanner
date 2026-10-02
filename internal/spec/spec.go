// Package spec reads a Swagger 2.0 or OpenAPI 3 document and turns its
// documented paths into concrete URLs to scan.
package spec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// DefaultParamValue fills path parameters that have no explicit value.
const DefaultParamValue = "1"

var httpMethods = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true,
	"options": true, "head": true, "patch": true, "trace": true,
}

var pathParam = regexp.MustCompile(`\{([^}]+)\}`)

// Spec is the part of an API document needed to build scan targets.
type Spec struct {
	// ServerURL is the server declared by the document; it may be empty or relative.
	ServerURL string
	Paths     []Path
}

// Path is a documented path template with its HTTP methods.
type Path struct {
	Template string
	Methods  []string
}

// Endpoint is a documented path resolved to a concrete URL.
type Endpoint struct {
	Path    string   `json:"path"`
	Methods []string `json:"methods"`
	URL     string   `json:"url"`
}

type document struct {
	Swagger  string   `json:"swagger" yaml:"swagger"`
	OpenAPI  string   `json:"openapi" yaml:"openapi"`
	Host     string   `json:"host" yaml:"host"`
	BasePath string   `json:"basePath" yaml:"basePath"`
	Schemes  []string `json:"schemes" yaml:"schemes"`
	Servers  []struct {
		URL string `json:"url" yaml:"url"`
	} `json:"servers" yaml:"servers"`
	Paths map[string]map[string]any `json:"paths" yaml:"paths"`
}

// Load reads a document from a local file or, for http(s) sources, over HTTP.
func Load(source string, client *http.Client) ([]byte, error) {
	if !isHTTP(source) {
		return os.ReadFile(source)
	}
	resp, err := client.Get(source)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: status %d", source, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// Parse decodes a JSON or YAML Swagger 2.0 / OpenAPI 3 document.
func Parse(data []byte) (*Spec, error) {
	var doc document
	var err error
	if trimmed := bytes.TrimSpace(data); len(trimmed) > 0 && trimmed[0] == '{' {
		err = json.Unmarshal(trimmed, &doc)
	} else {
		err = yaml.Unmarshal(data, &doc)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid document: %w", err)
	}
	if doc.Swagger == "" && doc.OpenAPI == "" {
		return nil, errors.New("not a Swagger/OpenAPI document: missing \"swagger\" or \"openapi\" field")
	}
	if len(doc.Paths) == 0 {
		return nil, errors.New("document has no paths")
	}

	s := &Spec{ServerURL: serverURL(doc)}
	for template, item := range doc.Paths {
		p := Path{Template: template}
		for key := range item {
			if httpMethods[strings.ToLower(key)] {
				p.Methods = append(p.Methods, strings.ToUpper(key))
			}
		}
		sort.Strings(p.Methods)
		s.Paths = append(s.Paths, p)
	}
	sort.Slice(s.Paths, func(i, j int) bool { return s.Paths[i].Template < s.Paths[j].Template })
	return s, nil
}

func serverURL(doc document) string {
	if doc.OpenAPI != "" {
		if len(doc.Servers) > 0 {
			return doc.Servers[0].URL
		}
		return ""
	}
	if doc.Host == "" {
		return doc.BasePath
	}
	scheme := "https"
	if len(doc.Schemes) > 0 {
		scheme = doc.Schemes[0]
	} else if isLocal(doc.Host) {
		scheme = "http"
	}
	return scheme + "://" + doc.Host + doc.BasePath
}

// ResolveBase picks the base URL to scan. The document's server is resolved
// against the document's own URL when relative. An override replaces scheme
// and host; its path, when set, replaces the server path too, so
// -base http://localhost:3000 tests a local copy of https://api.example.com/v1
// at http://localhost:3000/v1.
func ResolveBase(override, serverURL, source string) (string, error) {
	server, err := url.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("invalid server URL %q: %w", serverURL, err)
	}
	if override != "" {
		o, err := url.Parse(override)
		if err != nil || !isAbsolute(o) {
			return "", fmt.Errorf("invalid -base %q: must be an absolute http(s) URL", override)
		}
		if strings.Trim(o.Path, "/") == "" {
			o.Path = server.Path
		}
		return strings.TrimRight(o.String(), "/"), nil
	}
	if !isAbsolute(server) && isHTTP(source) {
		ref, err := url.Parse(source)
		if err != nil {
			return "", fmt.Errorf("invalid document URL %q: %w", source, err)
		}
		if serverURL == "" {
			server.Path = "/"
		}
		server = ref.ResolveReference(server)
	}
	if !isAbsolute(server) {
		return "", fmt.Errorf("the document declares no absolute server URL (got %q): pass -base, e.g. -base http://localhost:8080", serverURL)
	}
	return strings.TrimRight(server.String(), "/"), nil
}

// Endpoints builds one concrete URL per documented path. Path parameters take
// their value from params, falling back to DefaultParamValue.
func Endpoints(s *Spec, base string, params map[string]string) []Endpoint {
	endpoints := make([]Endpoint, 0, len(s.Paths))
	for _, p := range s.Paths {
		filled := pathParam.ReplaceAllStringFunc(p.Template, func(m string) string {
			if v, ok := params[m[1:len(m)-1]]; ok {
				return url.PathEscape(v)
			}
			return DefaultParamValue
		})
		endpoints = append(endpoints, Endpoint{
			Path:    p.Template,
			Methods: p.Methods,
			URL:     base + "/" + strings.TrimLeft(filled, "/"),
		})
	}
	return endpoints
}

func isHTTP(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func isAbsolute(u *url.URL) bool {
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func isLocal(host string) bool {
	h := host
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[:i]
	}
	return h == "localhost" || h == "0.0.0.0" || strings.HasPrefix(h, "127.")
}
