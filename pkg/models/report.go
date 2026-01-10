package models

type HeaderResult struct {
	Name           string   `json:"name"`
	Present        bool     `json:"present"`
	Value          *string  `json:"value"`
	Severity       Severity `json:"severity"`
	Recommendation *string  `json:"recommendation,omitempty"`
}

type Summary struct {
	TotalChecks int    `json:"total_checks"`
	Passed      int    `json:"passed"`
	Failed      int    `json:"failed"`
	Score       string `json:"score"`
}

type ScanResult struct {
	URL        string         `json:"url"`
	StatusCode int            `json:"status_code"`
	Error      *string        `json:"error,omitempty"`
	Headers    []HeaderResult `json:"headers,omitempty"`
	Summary    *Summary       `json:"summary,omitempty"`
}

type Report struct {
	ScanDate string       `json:"scan_date"`
	Results  []ScanResult `json:"results"`
}
