package handler

import (
	"net/http"
	"time"

	"http-header-security-scanner/internal/scanner"
	"http-header-security-scanner/pkg/models"

	"github.com/gin-gonic/gin"
)

// ScanRequest represents the request body for scanning URLs
// @Description Request body for HTTP header security scan
type ScanRequest struct {
	URLs        []string `json:"urls" binding:"required,min=1" example:"https://www.google.com,https://github.com"`
	Timeout     int      `json:"timeout,omitempty" example:"10"`
	Insecure    bool     `json:"insecure,omitempty" example:"false"`
	BearerToken string   `json:"bearer_token,omitempty" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// ErrorResponse represents an error response
// @Description Error response
type ErrorResponse struct {
	Error string `json:"error" example:"urls is required"`
}

type ScanHandler struct {
	defaultTimeout time.Duration
}

func NewScanHandler(defaultTimeout time.Duration) *ScanHandler {
	return &ScanHandler{
		defaultTimeout: defaultTimeout,
	}
}

// Scan godoc
// @Summary      Scan URLs for HTTP security headers
// @Description  Analyzes one or more URLs and returns a report on their HTTP security headers configuration
// @Tags         scan
// @Accept       json
// @Produce      json
// @Param        request body ScanRequest true "URLs to scan"
// @Success      200  {object}  models.Report
// @Failure      400  {object}  ErrorResponse
// @Router       /scan [post]
func (h *ScanHandler) Scan(ctx *gin.Context) {
	var req ScanRequest

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, ErrorResponse{
			Error: err.Error(),
		})
		return
	}

	timeout := h.defaultTimeout
	if req.Timeout > 0 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	opts := scanner.Options{
		Timeout:     timeout,
		Insecure:    req.Insecure,
		BearerToken: req.BearerToken,
	}

	results := make([]models.ScanResult, 0, len(req.URLs))
	for _, url := range req.URLs {
		result := scanner.Scan(url, opts)
		results = append(results, result)
	}

	report := models.Report{
		ScanDate: time.Now().UTC().Format(time.RFC3339),
		Results:  results,
	}

	ctx.JSON(http.StatusOK, report)
}
