package models

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityOK       Severity = "ok"
)

func (s Severity) String() string {
	return string(s)
}

func (s Severity) Priority() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	case SeverityOK:
		return 0
	default:
		return -1
	}
}
