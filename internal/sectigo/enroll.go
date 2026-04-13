package sectigo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// NotReadyError is returned by Collect when the certificate has not yet been
// issued by Sectigo (e.g. the enrollment is still being processed). The
// caller should retry after a delay.
type NotReadyError struct {
	SSLID   int
	Message string
}

// Error implements the error interface.
func (e *NotReadyError) Error() string {
	return fmt.Sprintf("certificate sslId=%d not ready: %s", e.SSLID, e.Message)
}

// IsNotReadyError reports whether err (or any error in its chain) is a
// *NotReadyError, meaning the certificate is not yet available for collection.
func IsNotReadyError(err error) bool {
	if err == nil {
		return false
	}
	target := &NotReadyError{}
	return errors.As(err, &target)
}

// Enroll submits a certificate signing request to the Sectigo API and returns
// the enrollment response containing the SSL ID. The SSL ID is later used to
// collect the issued certificate.
func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (*EnrollResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encoding enroll request: %w", err)
	}

	var resp EnrollResponse
	if err := c.doRequest(ctx, "POST", "/ssl/v1/enroll", bytes.NewReader(body), &resp); err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}

	return &resp, nil
}

// Collect retrieves the issued certificate in PEM format for the given SSL ID.
// If the certificate is not yet ready (HTTP 400 or an empty response), a
// *NotReadyError is returned so the caller can distinguish retryable
// "not-yet-issued" conditions from permanent failures.
func (c *Client) Collect(ctx context.Context, sslID int) ([]byte, error) {
	path := fmt.Sprintf("/ssl/v1/collect/%d/pem", sslID)

	data, err := c.doRequestRaw(ctx, "GET", path)
	if err != nil {
		// A 400 from the collect endpoint typically means the certificate is
		// still being processed.
		if apiErr, ok := err.(*APIError); ok && apiErr.StatusCode == 400 {
			return nil, &NotReadyError{
				SSLID:   sslID,
				Message: apiErr.Body,
			}
		}
		return nil, fmt.Errorf("collect: %w", err)
	}

	// An empty body also indicates the certificate is not ready yet.
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, &NotReadyError{
			SSLID:   sslID,
			Message: "empty response",
		}
	}

	return data, nil
}
