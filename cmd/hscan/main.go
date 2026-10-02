// Command hscan scans every endpoint documented in a Swagger/OpenAPI file
// and classifies each one by its missing HTTP security headers.
//
//	hscan -spec docs/swagger.json -base http://localhost:8080
//	hscan -spec http://localhost:8080/v3/api-docs -format markdown -out report.md
//
// Exit codes: 0 ok, 1 threshold set by -fail-on reached, 2 usage or input error.
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fraaancesco/http-header-security-scanner/internal/report"
	"github.com/fraaancesco/http-header-security-scanner/internal/scanner"
	"github.com/fraaancesco/http-header-security-scanner/internal/spec"
	"github.com/fraaancesco/http-header-security-scanner/pkg/models"
)

// exit and now are variables so tests can replace them.
var (
	exit = os.Exit
	now  = time.Now
)

func main() {
	exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type paramFlag map[string]string

func (p paramFlag) String() string { return "" }

func (p paramFlag) Set(v string) error {
	name, value, ok := strings.Cut(v, "=")
	if !ok || name == "" {
		return errors.New("expected name=value")
	}
	p[name] = value
	return nil
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hscan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	specSrc := fs.String("spec", "", "Swagger/OpenAPI document (JSON or YAML): file path or http(s) URL (required)")
	base := fs.String("base", "", "base URL to scan, e.g. http://localhost:8080 (default: the server declared by the document)")
	params := paramFlag{}
	fs.Var(params, "param", "value for a path parameter, name=value (repeatable; unset parameters use \""+spec.DefaultParamValue+"\")")
	token := fs.String("token", os.Getenv("HSCAN_TOKEN"), "bearer token sent to every endpoint (default $HSCAN_TOKEN)")
	timeout := fs.Int("timeout", 10, "per-request timeout in seconds")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification")
	concurrency := fs.Int("concurrency", 8, "parallel requests")
	format := fs.String("format", "text", "output format: text, markdown or json")
	out := fs.String("out", "", "write the report to this file; a text summary still goes to stdout")
	failOn := fs.String("fail-on", "none", "exit 1 if an endpoint is classified at or above: error, critical, high, medium, low or none")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	usageErr := func(msg string) int {
		fmt.Fprintln(stderr, "hscan:", msg)
		fs.Usage()
		return 2
	}
	switch {
	case *specSrc == "":
		return usageErr("-spec is required")
	case *format != "text" && *format != "markdown" && *format != "json":
		return usageErr("-format must be text, markdown or json")
	case *failOn != "none" && report.Rank(models.Severity(*failOn)) < 1:
		return usageErr("-fail-on must be error, critical, high, medium, low or none")
	case *timeout < 1 || *concurrency < 1:
		return usageErr("-timeout and -concurrency must be at least 1")
	}

	fail := func(err error) int {
		fmt.Fprintln(stderr, "hscan:", err)
		return 2
	}

	opts := scanner.Options{
		Timeout:     time.Duration(*timeout) * time.Second,
		Insecure:    *insecure,
		BearerToken: *token,
	}
	client := &http.Client{
		Timeout:   opts.Timeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.Insecure}},
	}

	data, err := spec.Load(*specSrc, client)
	if err != nil {
		return fail(err)
	}
	s, err := spec.Parse(data)
	if err != nil {
		return fail(err)
	}
	baseURL, err := spec.ResolveBase(*base, s.ServerURL, *specSrc)
	if err != nil {
		return fail(err)
	}

	endpoints := spec.Endpoints(s, baseURL, params)
	rep := report.New(*specSrc, baseURL, endpoints, scanAll(endpoints, opts, *concurrency))
	rep.ScanDate = now().UTC().Format(time.RFC3339)

	w := stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return fail(err)
		}
		defer f.Close()
		w = f
	}
	write := map[string]func(io.Writer) error{
		"text":     rep.WriteText,
		"markdown": rep.WriteMarkdown,
		"json":     rep.WriteJSON,
	}[*format]
	if err := write(w); err != nil {
		return fail(err)
	}
	if *out != "" {
		if err := rep.WriteText(stdout); err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "\nReport written to %s\n", *out)
	}

	if *failOn != "none" && rep.Fails(models.Severity(*failOn)) {
		return 1
	}
	return 0
}

// scanAll scans the endpoints in parallel; results keep the input order.
func scanAll(endpoints []spec.Endpoint, opts scanner.Options, workers int) []models.ScanResult {
	results := make([]models.ScanResult, len(endpoints))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for i := range jobs {
				results[i] = scanner.Scan(endpoints[i].URL, opts)
			}
		})
	}
	for i := range endpoints {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}
