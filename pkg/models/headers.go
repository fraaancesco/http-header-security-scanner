package models

type SecurityHeader struct {
	Name           string
	Severity       Severity
	Recommendation string
}

var SecurityHeaders = []SecurityHeader{
	// Critical
	{
		Name:           "Strict-Transport-Security",
		Severity:       SeverityCritical,
		Recommendation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to enforce HTTPS connections and prevent man-in-the-middle attacks.",
	},
	{
		Name:           "Content-Security-Policy",
		Severity:       SeverityCritical,
		Recommendation: "Add Content-Security-Policy header to prevent XSS and data injection attacks. Example: \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'\"",
	},

	// High
	{
		Name:           "X-Frame-Options",
		Severity:       SeverityHigh,
		Recommendation: "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to prevent clickjacking attacks.",
	},
	{
		Name:           "X-Content-Type-Options",
		Severity:       SeverityHigh,
		Recommendation: "Add 'X-Content-Type-Options: nosniff' to prevent MIME type sniffing attacks.",
	},
	{
		Name:           "Cross-Origin-Opener-Policy",
		Severity:       SeverityHigh,
		Recommendation: "Add 'Cross-Origin-Opener-Policy: same-origin' to isolate browsing context and prevent Spectre-like attacks.",
	},
	{
		Name:           "Cross-Origin-Resource-Policy",
		Severity:       SeverityHigh,
		Recommendation: "Add 'Cross-Origin-Resource-Policy: same-origin' to prevent resources from being loaded by other origins.",
	},
	{
		Name:           "Cross-Origin-Embedder-Policy",
		Severity:       SeverityHigh,
		Recommendation: "Add 'Cross-Origin-Embedder-Policy: require-corp' to prevent loading cross-origin resources without explicit permission.",
	},

	// Medium
	{
		Name:           "Referrer-Policy",
		Severity:       SeverityMedium,
		Recommendation: "Add 'Referrer-Policy: strict-origin-when-cross-origin' to control referrer information leakage.",
	},
	{
		Name:           "Permissions-Policy",
		Severity:       SeverityMedium,
		Recommendation: "Add Permissions-Policy header to control browser features. Example: \"geolocation=(), microphone=(), camera=(), payment=()\"",
	},
	{
		Name:           "Cache-Control",
		Severity:       SeverityMedium,
		Recommendation: "Add 'Cache-Control: no-store, no-cache, must-revalidate, private' for sensitive pages to prevent caching of sensitive data.",
	},
	{
		Name:           "Clear-Site-Data",
		Severity:       SeverityMedium,
		Recommendation: "Consider using 'Clear-Site-Data' header on logout endpoints to clear browsing data. Example: \"cache\", \"cookies\", \"storage\"",
	},

	// Low
	{
		Name:           "X-XSS-Protection",
		Severity:       SeverityLow,
		Recommendation: "Add 'X-XSS-Protection: 0' to disable flawed XSS auditor. Note: Modern browsers have removed XSS auditor; rely on CSP instead.",
	},
	{
		Name:           "X-Permitted-Cross-Domain-Policies",
		Severity:       SeverityLow,
		Recommendation: "Add 'X-Permitted-Cross-Domain-Policies: none' to prevent Adobe Flash and PDF from loading data from your domain.",
	},
	{
		Name:           "X-DNS-Prefetch-Control",
		Severity:       SeverityLow,
		Recommendation: "Add 'X-DNS-Prefetch-Control: off' to disable DNS prefetching and prevent information leakage.",
	},
	{
		Name:           "X-Download-Options",
		Severity:       SeverityLow,
		Recommendation: "Add 'X-Download-Options: noopen' to prevent IE from executing downloads in the site's context.",
	},
	{
		Name:           "Expect-CT",
		Severity:       SeverityLow,
		Recommendation: "Add 'Expect-CT: max-age=86400, enforce' to enforce Certificate Transparency. Note: Deprecated since June 2021, but still useful for older browsers.",
	},
	{
		Name:           "X-Robots-Tag",
		Severity:       SeverityLow,
		Recommendation: "Add 'X-Robots-Tag: noindex, nofollow' to prevent search engines from indexing sensitive pages.",
	},
	{
		Name:           "Origin-Agent-Cluster",
		Severity:       SeverityLow,
		Recommendation: "Add 'Origin-Agent-Cluster: ?1' to request the browser to isolate the origin for better security and performance.",
	},
	{
		Name:           "Timing-Allow-Origin",
		Severity:       SeverityLow,
		Recommendation: "Consider 'Timing-Allow-Origin' to control which origins can access timing information via Resource Timing API.",
	},
	{
		Name:           "Content-Disposition",
		Severity:       SeverityLow,
		Recommendation: "Use 'Content-Disposition: attachment; filename=\"file.ext\"' to force download instead of inline rendering for user-uploaded files.",
	},
	{
		Name:           "NEL",
		Severity:       SeverityLow,
		Recommendation: "Add Network Error Logging (NEL) header to collect reports about network errors. Example: '{\"report_to\":\"default\",\"max_age\":31536000}'",
	},
	{
		Name:           "Report-To",
		Severity:       SeverityLow,
		Recommendation: "Add 'Report-To' header to define endpoints for receiving CSP, COOP, COEP violation reports.",
	},
	{
		Name:           "Content-Security-Policy-Report-Only",
		Severity:       SeverityLow,
		Recommendation: "Use 'Content-Security-Policy-Report-Only' to test CSP policies without blocking content. Useful for gradual CSP deployment.",
	},
}
