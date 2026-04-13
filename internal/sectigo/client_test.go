package sectigo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	// Verify that NewClient returns a non-nil client with the correct base URL.
	c := NewClient("https://api.example.com", "https://auth.example.com/token", "id", "secret")
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if c.baseURL != "https://api.example.com" {
		t.Errorf("unexpected baseURL: %s", c.baseURL)
	}
	if c.httpClient == nil {
		t.Fatal("expected non-nil httpClient")
	}
}

func TestNewClientWithHTTP(t *testing.T) {
	hc := &http.Client{}
	c := NewClientWithHTTP("https://api.example.com", hc)
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if c.httpClient != hc {
		t.Error("expected the provided http.Client to be used")
	}
}

func TestDoRequest_Success(t *testing.T) {
	// Set up a test server that returns a JSON response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]int{"sslId": 42})
	}))
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())

	var dest EnrollResponse
	err := c.doRequest(context.Background(), "GET", "/test", nil, &dest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dest.SSLID != 42 {
		t.Errorf("expected sslId=42, got %d", dest.SSLID)
	}
}

func TestDoRequest_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("access denied"))
	}))
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())

	err := c.doRequest(context.Background(), "GET", "/test", nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 403 {
		t.Errorf("expected status 403, got %d", apiErr.StatusCode)
	}
	if apiErr.Body != "access denied" {
		t.Errorf("unexpected body: %s", apiErr.Body)
	}
}

func TestDoRequestRaw_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"))
	}))
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())

	data, err := c.doRequestRaw(context.Background(), "GET", "/collect")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty response")
	}
}

func TestDoRequestRaw_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	c := NewClientWithHTTP(srv.URL, srv.Client())

	_, err := c.doRequestRaw(context.Background(), "GET", "/collect")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != 500 {
		t.Errorf("expected status 500, got %d", apiErr.StatusCode)
	}
}
