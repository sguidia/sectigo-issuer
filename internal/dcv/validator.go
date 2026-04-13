// Package dcv provides Domain Control Validation interfaces for future implementation.
// In v1, DCV is not automated — domains must be pre-validated in Sectigo.
package dcv

import "context"

// ValidationStatus represents the current DCV status for a domain.
type ValidationStatus struct {
	Domain         string
	Status         string // VALIDATED, NOT_VALIDATED, EXPIRED
	ExpirationDate string
}

// ValidationChallenge contains the HTTP validation challenge details
// returned by Sectigo for domain ownership proof.
type ValidationChallenge struct {
	URL        string
	FirstLine  string
	SecondLine string
}

// Validator defines the interface for Domain Control Validation operations.
// Implementations will interact with the Sectigo DCV API to check domain
// validation status and initiate validation challenges.
type Validator interface {
	// CheckStatus queries the current DCV status for the given domain.
	CheckStatus(ctx context.Context, domain string) (*ValidationStatus, error)

	// StartHTTPSValidation initiates an HTTPS-based domain validation challenge.
	StartHTTPSValidation(ctx context.Context, domain string) (*ValidationChallenge, error)

	// SubmitValidation notifies Sectigo that the validation challenge has been fulfilled
	// and requests status re-evaluation.
	SubmitValidation(ctx context.Context, domain string) (*ValidationStatus, error)
}
