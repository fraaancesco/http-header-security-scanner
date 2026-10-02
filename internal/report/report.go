// Package report classifies scanned endpoints and renders a compact summary.
package report

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/fraaancesco/http-header-security-scanner/internal/spec"
	"github.com/fraaancesco/http-header-security-scanner/pkg/models"
)

// SeverityError classifies an endpoint that could not be reached.
const SeverityError models.Severity = "error"

// Classes lists every class, worst first.
var Classes = []models.Severity{
	SeverityError,
	models.SeverityCritical,
	models.SeverityHigh,
	models.SeverityMedium,
	models.SeverityLow,
	models.SeverityOK,
}

// Entry is one scanned endpoint with its class.
type Entry struct {
	spec.Endpoint
	Class  models.Severity   `json:"class"`
	Result models.ScanResult `json:"result"`
}

// Report is the outcome of scanning every documented endpoint.
type Report struct {
	ScanDate string                  `json:"scan_date,omitempty"`
	Source   string                  `json:"source"`
	Base     string                  `json:"base"`
	Counts   map[models.Severity]int `json:"counts"`
	Entries  []Entry                 `json:"endpoints"`
}

// Rank orders classes: error above critical, ok lowest.
func Rank(s models.Severity) int {
	if s == SeverityError {
		return 5
	}
	return s.Priority()
}

// Classify returns the worst severity among the missing headers, ok when
// nothing is missing, or SeverityError when the endpoint was unreachable.
func Classify(r models.ScanResult) models.Severity {
	if r.Error != nil {
		return SeverityError
	}
	worst := models.SeverityOK
	for _, h := range r.Headers {
		if !h.Present && h.Severity.Priority() > worst.Priority() {
			worst = h.Severity
		}
	}
	return worst
}

// New builds a report; results[i] must belong to endpoints[i]. Entries are
// sorted worst first, then by path.
func New(source, base string, endpoints []spec.Endpoint, results []models.ScanResult) *Report {
	r := &Report{Source: source, Base: base, Counts: map[models.Severity]int{}}
	for _, c := range Classes {
		r.Counts[c] = 0
	}
	for i, e := range endpoints {
		class := Classify(results[i])
		r.Counts[class]++
		r.Entries = append(r.Entries, Entry{Endpoint: e, Class: class, Result: results[i]})
	}
	slices.SortStableFunc(r.Entries, func(a, b Entry) int {
		return cmp.Or(
			cmp.Compare(Rank(b.Class), Rank(a.Class)),
			strings.Compare(a.Path, b.Path),
		)
	})
	return r
}

// Fails reports whether any endpoint is classified at or above threshold.
func (r *Report) Fails(threshold models.Severity) bool {
	for _, e := range r.Entries {
		if Rank(e.Class) >= Rank(threshold) {
			return true
		}
	}
	return false
}

// WriteJSON writes the full report, including every header result.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText writes a compact summary: one line per endpoint, the headers
// missing everywhere (usually fixed once in a shared middleware), the
// per-endpoint differences and the errors.
func (r *Report) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	fmt.Fprintf(tw, "%d endpoints from %s, base %s (GET only, no request bodies)\n\n", len(r.Entries), r.Source, r.Base)
	fmt.Fprintln(tw, "CLASS\tSCORE\tSTATUS\tMETHODS\tPATH")
	for _, e := range r.Entries {
		score, status := "-", "-"
		if e.Result.Error == nil {
			score, status = e.Result.Summary.Score, fmt.Sprint(e.Result.StatusCode)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", e.Class, score, status, strings.Join(e.Methods, ","), e.Path)
	}

	common := r.commonMissing()
	if len(common) > 0 {
		fmt.Fprintln(tw, "\nMissing on every reachable endpoint (fix once, e.g. in a shared middleware):")
		for _, sev := range Classes[1:5] {
			names := missingOf(common, sev)
			if len(names) == 0 {
				continue
			}
			if sev == models.SeverityLow {
				fmt.Fprintf(tw, "  %s\t%d headers (see -format json)\n", sev, len(names))
				continue
			}
			fmt.Fprintf(tw, "  %s\t%s\n", sev, strings.Join(names, ", "))
		}
	}

	if extras := r.extras(common); len(extras) > 0 {
		fmt.Fprintln(tw, "\nAlso missing on single endpoints:")
		for _, x := range extras {
			fmt.Fprintf(tw, "  %s\t%s\n", x.path, x.text)
		}
	}

	if r.Counts[SeverityError] > 0 {
		fmt.Fprintln(tw, "\nErrors:")
		for _, e := range r.Entries {
			if e.Result.Error != nil {
				fmt.Fprintf(tw, "  %s\t%s\n", e.Path, *e.Result.Error)
			}
		}
	}

	totals := make([]string, 0, len(Classes))
	for _, c := range Classes {
		totals = append(totals, fmt.Sprintf("%s %d", c, r.Counts[c]))
	}
	fmt.Fprintf(tw, "\nTotals: %s\n", strings.Join(totals, ", "))

	return tw.Flush()
}

// classMeaning explains each class in the Markdown report.
var classMeaning = map[models.Severity]string{
	SeverityError:           "Could not be reached, so it was not checked.",
	models.SeverityCritical: "Exposed to direct attacks such as HTTPS downgrade and unrestricted script injection.",
	models.SeverityHigh:     "Exposed to clickjacking, MIME sniffing or cross-origin attacks.",
	models.SeverityMedium:   "Exposed to data leaks through referrers, caches or browser features.",
	models.SeverityLow:      "Only legacy-browser hardening or monitoring headers are missing.",
	models.SeverityOK:       "Every checked header is present.",
}

// WriteMarkdown writes a shareable report: totals with their meaning, one
// table row per endpoint, the headers missing everywhere, the per-endpoint
// differences, the risk and fix of every missing header, and the errors.
func (r *Report) WriteMarkdown(w io.Writer) error {
	var b strings.Builder

	b.WriteString("# HTTP security headers report\n\n")
	if r.ScanDate != "" {
		fmt.Fprintf(&b, "- **Date:** %s\n", r.ScanDate)
	}
	fmt.Fprintf(&b, "- **Spec:** `%s`\n", r.Source)
	fmt.Fprintf(&b, "- **Base URL:** `%s`\n", r.Base)
	fmt.Fprintf(&b, "- **Endpoints:** %d (GET only, no request bodies)\n\n", len(r.Entries))
	b.WriteString("Each endpoint is classified by the most severe header it is missing. ")
	b.WriteString("This report covers HTTP security headers only; it is not a complete security review.\n\n")

	b.WriteString("## Totals\n\n| Class | Endpoints | Meaning |\n|---|---|---|\n")
	for _, c := range Classes {
		fmt.Fprintf(&b, "| %s | %d | %s |\n", c, r.Counts[c], classMeaning[c])
	}

	b.WriteString("\n## Endpoints\n\n| Class | Score | Status | Methods | Path |\n|---|---|---|---|---|\n")
	for _, e := range r.Entries {
		score, status := "-", "-"
		if e.Result.Error == nil {
			score, status = e.Result.Summary.Score, fmt.Sprint(e.Result.StatusCode)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | `%s` |\n", e.Class, score, status, strings.Join(e.Methods, ", "), e.Path)
	}

	common := r.commonMissing()
	if len(common) > 0 {
		b.WriteString("\n## Missing on every reachable endpoint\n\n")
		b.WriteString("These are usually fixed once, in a shared middleware or in the reverse proxy.\n\n")
		b.WriteString("| Severity | Headers |\n|---|---|\n")
		for _, sev := range Classes[1:5] {
			if names := missingOf(common, sev); len(names) > 0 {
				fmt.Fprintf(&b, "| %s | %s |\n", sev, "`"+strings.Join(names, "`, `")+"`")
			}
		}
	}

	if extras := r.extras(common); len(extras) > 0 {
		b.WriteString("\n## Also missing on single endpoints\n\n")
		for _, x := range extras {
			fmt.Fprintf(&b, "- `%s`: %s\n", x.path, x.text)
		}
	}

	if missing := r.missingOn(); len(missing) > 0 {
		b.WriteString("\n## Risks and recommendations\n\n")
		b.WriteString("What each missing header exposes you to, most severe first, and how to fix it.\n")
		for _, h := range models.SecurityHeaders {
			paths, ok := missing[h.Name]
			if !ok {
				continue
			}
			where := "all reachable endpoints"
			if !common[h.Name] {
				where = "`" + strings.Join(paths, "`, `") + "`"
			}
			fmt.Fprintf(&b, "\n### `%s` (%s)\n\n", h.Name, h.Severity)
			fmt.Fprintf(&b, "- **Risk:** %s\n", h.Risk)
			fmt.Fprintf(&b, "- **Recommendation:** %s\n", h.Recommendation)
			fmt.Fprintf(&b, "- **Missing on:** %s\n", where)
		}
	}

	if r.Counts[SeverityError] > 0 {
		b.WriteString("\n## Errors\n\n")
		for _, e := range r.Entries {
			if e.Result.Error != nil {
				fmt.Fprintf(&b, "- `%s`: %s\n", e.Path, *e.Result.Error)
			}
		}
	}

	_, err := io.WriteString(w, b.String())
	return err
}

// missingOn maps each header missing on at least one reachable endpoint to
// the paths that miss it.
func (r *Report) missingOn() map[string][]string {
	out := map[string][]string{}
	for _, e := range r.Entries {
		if e.Result.Error != nil {
			continue
		}
		for _, h := range e.Result.Headers {
			if !h.Present {
				out[h.Name] = append(out[h.Name], e.Path)
			}
		}
	}
	return out
}

type extra struct{ path, text string }

// extras lists, per reachable endpoint, the critical, high and medium headers
// it misses beyond those in common.
func (r *Report) extras(common map[string]bool) []extra {
	var out []extra
	for _, e := range r.Entries {
		if e.Result.Error != nil {
			continue
		}
		var parts []string
		for _, sev := range Classes[1:4] {
			var names []string
			for _, h := range e.Result.Headers {
				if !h.Present && h.Severity == sev && !common[h.Name] {
					names = append(names, h.Name)
				}
			}
			if len(names) > 0 {
				parts = append(parts, fmt.Sprintf("%s: %s", sev, strings.Join(names, ", ")))
			}
		}
		if len(parts) > 0 {
			out = append(out, extra{e.Path, strings.Join(parts, "; ")})
		}
	}
	return out
}

// commonMissing returns the headers missing on every reachable endpoint,
// keyed by name.
func (r *Report) commonMissing() map[string]bool {
	var common map[string]bool
	for _, e := range r.Entries {
		if e.Result.Error != nil {
			continue
		}
		missing := map[string]bool{}
		for _, h := range e.Result.Headers {
			if !h.Present && (common == nil || common[h.Name]) {
				missing[h.Name] = true
			}
		}
		common = missing
	}
	return common
}

// missingOf lists, in the canonical header order, the names in set that have
// the given severity.
func missingOf(set map[string]bool, sev models.Severity) []string {
	var names []string
	for _, h := range models.SecurityHeaders {
		if h.Severity == sev && set[h.Name] {
			names = append(names, h.Name)
		}
	}
	return names
}
