// Package sectigo implements an HTTP client for the Sectigo Certificate
// Manager REST API. It handles OAuth2 client-credentials authentication
// and exposes Enroll / Collect operations used by the issuer controller.
package sectigo

import "fmt"

// EnrollRequest contains the parameters sent to the Sectigo SSL enrollment
// endpoint (POST /ssl/v1/enroll).
type EnrollRequest struct {
	OrgID             int    `json:"orgId"`
	CSR               string `json:"csr"`
	CertType          int    `json:"certType"`
	Term              int    `json:"term"`
	SubjAltNames      string `json:"subjAltNames,omitempty"`
	ExternalRequester string `json:"externalRequester,omitempty"`
}

// EnrollResponse is returned by the Sectigo API after a successful enrollment.
type EnrollResponse struct {
	SSLID int `json:"sslId"`
}

// APIError represents an error response from the Sectigo API. It carries the
// HTTP status code and the raw body so callers can inspect the details.
type APIError struct {
	StatusCode int
	Body       string
}

// Error implements the error interface.
func (e *APIError) Error() string {
	return fmt.Sprintf("sectigo API error: status %d: %s", e.StatusCode, e.Body)
}
