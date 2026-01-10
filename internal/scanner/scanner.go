package scanner

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"http-header-security-scanner/pkg/models"
)

type Options struct {
	Timeout     time.Duration
	Insecure    bool
	BearerToken string
}

func DefaultOptions() Options {
	return Options{
		Timeout:  10 * time.Second,
		Insecure: false,
	}
}

func Scan(url string, opts Options) models.ScanResult {
	result := models.ScanResult{
		URL: url,
	}

	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: opts.Insecure,
			},
		},
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		errStr := err.Error()
		result.Error = &errStr
		return result
	}

	if opts.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+opts.BearerToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		errStr := err.Error()
		result.Error = &errStr
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Headers = checkHeaders(resp.Header)
	result.Summary = calculateSummary(result.Headers)

	return result
}

func checkHeaders(respHeaders http.Header) []models.HeaderResult {
	results := make([]models.HeaderResult, 0, len(models.SecurityHeaders))

	for _, secHeader := range models.SecurityHeaders {
		headerResult := models.HeaderResult{
			Name: secHeader.Name,
		}

		value := respHeaders.Get(secHeader.Name)
		if value != "" {
			headerResult.Present = true
			headerResult.Value = &value
			headerResult.Severity = models.SeverityOK
		} else {
			headerResult.Present = false
			headerResult.Severity = secHeader.Severity
			headerResult.Recommendation = &secHeader.Recommendation
		}

		results = append(results, headerResult)
	}

	return results
}

func calculateSummary(headerResults []models.HeaderResult) *models.Summary {
	total := len(headerResults)
	passed := 0

	for _, h := range headerResults {
		if h.Present {
			passed++
		}
	}

	failed := total - passed
	score := float64(passed) / float64(total) * 100

	return &models.Summary{
		TotalChecks: total,
		Passed:      passed,
		Failed:      failed,
		Score:       fmt.Sprintf("%.0f%%", score),
	}
}
