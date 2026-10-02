package models

type SecurityHeader struct {
	Name           string
	Severity       Severity
	Risk           string // what the site is exposed to while the header is missing
	Recommendation string
}

var SecurityHeaders = []SecurityHeader{
	// Critical
	{
		Name:           "Strict-Transport-Security",
		Severity:       SeverityCritical,
		Risk:           "Browsers may reach the site over plain HTTP first, so an attacker on the network (public Wi-Fi, compromised router) can downgrade the connection with SSL stripping and read or modify the traffic, including session cookies and credentials.",
		Recommendation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to enforce HTTPS connections and prevent man-in-the-middle attacks.",
	},
	{
		Name:           "Content-Security-Policy",
		Severity:       SeverityCritical,
		Risk:           "There is no second line of defence against cross-site scripting: any injected script runs with full access to the page and can steal session tokens, act on behalf of the user or load malicious resources.",
		Recommendation: "Add Content-Security-Policy header to prevent XSS and data injection attacks. Example: \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'\"",
	},

	// High
	{
		Name:           "X-Frame-Options",
		Severity:       SeverityHigh,
		Risk:           "Any site can embed the page in an invisible iframe (clickjacking) and trick users into clicking buttons they cannot see, such as confirming an action or changing account settings.",
		Recommendation: "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to prevent clickjacking attacks.",
	},
	{
		Name:           "X-Content-Type-Options",
		Severity:       SeverityHigh,
		Risk:           "Browsers may MIME-sniff responses and execute user-controlled content (for example an uploaded file) as HTML or JavaScript, turning it into a cross-site scripting vector.",
		Recommendation: "Add 'X-Content-Type-Options: nosniff' to prevent MIME type sniffing attacks.",
	},
	{
		Name:           "Cross-Origin-Opener-Policy",
		Severity:       SeverityHigh,
		Risk:           "Cross-origin windows keep a reference to the page (window.opener), which enables tabnabbing and cross-site leaks and prevents the browser from isolating the page against Spectre-like side-channel attacks.",
		Recommendation: "Add 'Cross-Origin-Opener-Policy: same-origin' to isolate browsing context and prevent Spectre-like attacks.",
	},
	{
		Name:           "Cross-Origin-Resource-Policy",
		Severity:       SeverityHigh,
		Risk:           "Any other site can load these responses as images or scripts, bringing the data into its own process where it is exposed to Spectre-like side-channel attacks and cross-site leaks.",
		Recommendation: "Add 'Cross-Origin-Resource-Policy: same-origin' to prevent resources from being loaded by other origins.",
	},
	{
		Name:           "Cross-Origin-Embedder-Policy",
		Severity:       SeverityHigh,
		Risk:           "The page cannot be cross-origin isolated: it loads cross-origin resources without their explicit consent and remains more exposed to side-channel attacks.",
		Recommendation: "Add 'Cross-Origin-Embedder-Policy: require-corp' to prevent loading cross-origin resources without explicit permission.",
	},

	// Medium
	{
		Name:           "Referrer-Policy",
		Severity:       SeverityMedium,
		Risk:           "Full URLs, including paths and query strings that may contain tokens, identifiers or personal data, can be sent to third-party sites in the Referer header, especially by older browsers.",
		Recommendation: "Add 'Referrer-Policy: strict-origin-when-cross-origin' to control referrer information leakage.",
	},
	{
		Name:           "Permissions-Policy",
		Severity:       SeverityMedium,
		Risk:           "Embedded third-party content or injected scripts can request powerful browser features such as camera, microphone, geolocation or payment, because the site does not restrict them.",
		Recommendation: "Add Permissions-Policy header to control browser features. Example: \"geolocation=(), microphone=(), camera=(), payment=()\"",
	},
	{
		Name:           "Cache-Control",
		Severity:       SeverityMedium,
		Risk:           "Responses containing sensitive data may be stored by the browser, shared proxies or CDNs and later served to other users or read by someone else on a shared computer.",
		Recommendation: "Add 'Cache-Control: no-store, no-cache, must-revalidate, private' for sensitive pages to prevent caching of sensitive data.",
	},
	{
		Name:           "Clear-Site-Data",
		Severity:       SeverityMedium,
		Risk:           "After logout, cookies, storage and cached data may stay in the browser and be reused by the next person on the same device.",
		Recommendation: "Consider using 'Clear-Site-Data' header on logout endpoints to clear browsing data. Example: \"cache\", \"cookies\", \"storage\"",
	},

	// Low
	{
		Name:           "X-XSS-Protection",
		Severity:       SeverityLow,
		Risk:           "Outdated browsers may run their legacy XSS auditor, which attackers can abuse to disable scripts selectively or leak information. The risk is limited to old browsers.",
		Recommendation: "Add 'X-XSS-Protection: 0' to disable flawed XSS auditor. Note: Modern browsers have removed XSS auditor; rely on CSP instead.",
	},
	{
		Name:           "X-Permitted-Cross-Domain-Policies",
		Severity:       SeverityLow,
		Risk:           "Legacy Adobe Flash and PDF clients may honour cross-domain policy files on the site and read its data from other origins.",
		Recommendation: "Add 'X-Permitted-Cross-Domain-Policies: none' to prevent Adobe Flash and PDF from loading data from your domain.",
	},
	{
		Name:           "X-DNS-Prefetch-Control",
		Severity:       SeverityLow,
		Risk:           "The browser resolves the domains of links on the page in advance, revealing to DNS resolvers which external sites the user might visit.",
		Recommendation: "Add 'X-DNS-Prefetch-Control: off' to disable DNS prefetching and prevent information leakage.",
	},
	{
		Name:           "X-Download-Options",
		Severity:       SeverityLow,
		Risk:           "In legacy Internet Explorer, downloaded files can be opened directly in the site's context, so a malicious HTML file could run with the site's privileges.",
		Recommendation: "Add 'X-Download-Options: noopen' to prevent IE from executing downloads in the site's context.",
	},
	{
		Name:           "Expect-CT",
		Severity:       SeverityLow,
		Risk:           "Very old browsers do not enforce Certificate Transparency, making a misissued certificate for the domain harder to detect. Modern browsers enforce it by default, so the practical risk is minimal.",
		Recommendation: "Add 'Expect-CT: max-age=86400, enforce' to enforce Certificate Transparency. Note: Deprecated since June 2021, but still useful for older browsers.",
	},
	{
		Name:           "X-Robots-Tag",
		Severity:       SeverityLow,
		Risk:           "Search engines may index API responses or private pages that are publicly reachable and expose them in search results.",
		Recommendation: "Add 'X-Robots-Tag: noindex, nofollow' to prevent search engines from indexing sensitive pages.",
	},
	{
		Name:           "Origin-Agent-Cluster",
		Severity:       SeverityLow,
		Risk:           "The browser may keep the origin in the same agent cluster as other same-site origins, which weakens isolation against side-channel attacks and still allows document.domain changes.",
		Recommendation: "Add 'Origin-Agent-Cluster: ?1' to request the browser to isolate the origin for better security and performance.",
	},
	{
		Name:           "Timing-Allow-Origin",
		Severity:       SeverityLow,
		Risk:           "No direct risk: without this header other origins cannot read detailed resource timing. Set it only for cross-origin performance monitoring, and never to '*' on sensitive resources.",
		Recommendation: "Consider 'Timing-Allow-Origin' to control which origins can access timing information via Resource Timing API.",
	},
	{
		Name:           "Content-Disposition",
		Severity:       SeverityLow,
		Risk:           "User-uploaded or generated files may be rendered inline by the browser; if they contain HTML or scripts, these run in the site's origin (stored cross-site scripting).",
		Recommendation: "Use 'Content-Disposition: attachment; filename=\"file.ext\"' to force download instead of inline rendering for user-uploaded files.",
	},
	{
		Name:           "NEL",
		Severity:       SeverityLow,
		Risk:           "No direct vulnerability, but network failures seen by users (DNS, TLS or connection errors, possible interception) go unreported, so attacks or outages can go unnoticed.",
		Recommendation: "Add Network Error Logging (NEL) header to collect reports about network errors. Example: '{\"report_to\":\"default\",\"max_age\":31536000}'",
	},
	{
		Name:           "Report-To",
		Severity:       SeverityLow,
		Risk:           "No direct vulnerability, but CSP, COOP and COEP violations are not reported, so attacks attempted or blocked in users' browsers stay invisible.",
		Recommendation: "Add 'Report-To' header to define endpoints for receiving CSP, COOP, COEP violation reports.",
	},
	{
		Name:           "Content-Security-Policy-Report-Only",
		Severity:       SeverityLow,
		Risk:           "No direct vulnerability, but without a report-only policy the CSP cannot be tested safely before enforcing it, which often leads to a policy that is too permissive.",
		Recommendation: "Use 'Content-Security-Policy-Report-Only' to test CSP policies without blocking content. Useful for gradual CSP deployment.",
	},
}
