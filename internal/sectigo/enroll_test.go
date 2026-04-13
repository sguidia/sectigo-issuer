package sectigo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEnroll_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and path.
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/ssl/v1/enroll") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		// Verify the request body is valid JSON with expected fields.
		var req EnrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if req.OrgID != 123 {
			t.Errorf("expected orgId=123, got %d", req.OrgID)
		}
		if req.CertType != 1 {
			t.Errorf("expected certType=1, got %d", req.CertType)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(EnrollResponse{SSLID: 99999})
	}))
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())

	resp, err := c.Enroll(context.Background(), EnrollRequest{
		OrgID:    123,
		CSR:      "-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
		CertType: 1,
		Term:     365,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.SSLID != 99999 {
		t.Errorf("expected sslId=99999, got %d", resp.SSLID)
	}
}

func TestEnroll_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"description":"Invalid CSR"}`))
	}))
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())

	_, err := c.Enroll(context.Background(), EnrollRequest{
		OrgID:    123,
		CSR:      "bad-csr",
		CertType: 1,
		Term:     365,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// The error should contain the API error details.
	if !strings.Contains(err.Error(), "Invalid CSR") {
		t.Errorf("expected error to contain 'Invalid CSR', got: %s", err.Error())
	}
}

func TestCollect_Ready(t *testing.T) {
	pemData := "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/ssl/v1/collect/12345/pem") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(pemData))
	}))
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())

	data, err := c.Collect(context.Background(), 12345)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != pemData {
		t.Errorf("unexpected PEM data:\ngot:  %s\nwant: %s", string(data), pemData)
	}
}

func TestCollect_NotReady_400(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Being processed by Sectigo"))
	}))
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())

	_, err := c.Collect(context.Background(), 12345)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !IsNotReadyError(err) {
		t.Errorf("expected NotReadyError, got: %T: %v", err, err)
	}

	nrErr, ok := err.(*NotReadyError)
	if !ok {
		t.Fatalf("expected *NotReadyError, got %T", err)
	}
	if nrErr.SSLID != 12345 {
		t.Errorf("expected sslId=12345, got %d", nrErr.SSLID)
	}
}

func TestCollect_NotReady_EmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Empty body — certificate not ready.
	}))
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())

	_, err := c.Collect(context.Background(), 12345)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !IsNotReadyError(err) {
		t.Errorf("expected NotReadyError, got: %T: %v", err, err)
	}
}

func TestCollect_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("server error"))
	}))
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())

	_, err := c.Collect(context.Background(), 12345)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// A 500 is not a NotReadyError — it is a real failure.
	if IsNotReadyError(err) {
		t.Error("500 should not be treated as NotReadyError")
	}
}

func TestIsNotReadyError_Nil(t *testing.T) {
	if IsNotReadyError(nil) {
		t.Error("expected false for nil error")
	}
}
