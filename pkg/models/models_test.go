package models

import "testing"

func TestSeverityString(t *testing.T) {
	if got := SeverityCritical.String(); got != "critical" {
		t.Errorf("String() = %q, want critical", got)
	}
}

func TestSeverityPriority(t *testing.T) {
	tests := []struct {
		s    Severity
		want int
	}{
		{SeverityCritical, 4},
		{SeverityHigh, 3},
		{SeverityMedium, 2},
		{SeverityLow, 1},
		{SeverityOK, 0},
		{Severity("unknown"), -1},
	}
	for _, tt := range tests {
		if got := tt.s.Priority(); got != tt.want {
			t.Errorf("%q.Priority() = %d, want %d", tt.s, got, tt.want)
		}
	}
}

func TestSecurityHeadersAreWellFormed(t *testing.T) {
	if len(SecurityHeaders) == 0 {
		t.Fatal("SecurityHeaders is empty")
	}
	seen := map[string]bool{}
	for _, h := range SecurityHeaders {
		if h.Name == "" || h.Risk == "" || h.Recommendation == "" {
			t.Errorf("header %+v has empty name, risk or recommendation", h)
		}
		if seen[h.Name] {
			t.Errorf("duplicate header %q", h.Name)
		}
		seen[h.Name] = true
		if p := h.Severity.Priority(); p < 1 {
			t.Errorf("header %q has invalid severity %q", h.Name, h.Severity)
		}
	}
}
