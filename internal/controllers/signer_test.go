package controllers

import (
	"crypto/x509"
	"net"
	"testing"

	"github.com/cert-manager/issuer-lib/controllers/signer"

	sectigoissuerapi "github.com/sguidia/sectigo-issuer/api/v1alpha1"
)

func TestClientFromSpecAndSecret_MissingClientID(t *testing.T) {
	spec := &sectigoissuerapi.SectigoIssuerSpec{
		URL:      "https://example.com/api",
		TokenURL: "https://example.com/token",
	}
	secretData := map[string][]byte{
		"client-secret": []byte("s3cret"),
	}

	_, err := clientFromSpecAndSecret(spec, secretData)
	if err == nil {
		t.Fatal("expected error for missing client-id, got nil")
	}
	if _, ok := err.(signer.PermanentError); !ok {
		t.Fatalf("expected PermanentError, got %T: %v", err, err)
	}
}

func TestClientFromSpecAndSecret_MissingClientSecret(t *testing.T) {
	spec := &sectigoissuerapi.SectigoIssuerSpec{
		URL:      "https://example.com/api",
		TokenURL: "https://example.com/token",
	}
	secretData := map[string][]byte{
		"client-id": []byte("myid"),
	}

	_, err := clientFromSpecAndSecret(spec, secretData)
	if err == nil {
		t.Fatal("expected error for missing client-secret, got nil")
	}
	if _, ok := err.(signer.PermanentError); !ok {
		t.Fatalf("expected PermanentError, got %T: %v", err, err)
	}
}

func TestClientFromSpecAndSecret_EmptyClientID(t *testing.T) {
	spec := &sectigoissuerapi.SectigoIssuerSpec{
		URL:      "https://example.com/api",
		TokenURL: "https://example.com/token",
	}
	secretData := map[string][]byte{
		"client-id":     []byte(""),
		"client-secret": []byte("s3cret"),
	}

	_, err := clientFromSpecAndSecret(spec, secretData)
	if err == nil {
		t.Fatal("expected error for empty client-id, got nil")
	}
}

func TestClientFromSpecAndSecret_Success(t *testing.T) {
	spec := &sectigoissuerapi.SectigoIssuerSpec{
		URL:      "https://example.com/api",
		TokenURL: "https://example.com/token",
	}
	secretData := map[string][]byte{
		"client-id":     []byte("myid"),
		"client-secret": []byte("s3cret"),
	}

	client, err := clientFromSpecAndSecret(spec, secretData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestExtractCSRFromPEM_NoPEM(t *testing.T) {
	_, err := extractCSRFromPEM([]byte("not pem data"))
	if err == nil {
		t.Fatal("expected error for invalid PEM, got nil")
	}
}

func TestExtractCSRFromPEM_WrongType(t *testing.T) {
	pemData := []byte("-----BEGIN CERTIFICATE-----\nMQ==\n-----END CERTIFICATE-----\n")
	_, err := extractCSRFromPEM(pemData)
	if err == nil {
		t.Fatal("expected error for wrong PEM type, got nil")
	}
}

func TestBuildSANs_DNSOnly(t *testing.T) {
	csr := &x509.CertificateRequest{
		DNSNames: []string{"example.com", "www.example.com"},
	}
	got := buildSANs(csr)
	expected := "example.com,www.example.com"
	if got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestBuildSANs_IPOnly(t *testing.T) {
	csr := &x509.CertificateRequest{
		IPAddresses: []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("192.168.1.1")},
	}
	got := buildSANs(csr)
	expected := "10.0.0.1,192.168.1.1"
	if got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestBuildSANs_Mixed(t *testing.T) {
	csr := &x509.CertificateRequest{
		DNSNames:    []string{"example.com"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
	}
	got := buildSANs(csr)
	expected := "example.com,10.0.0.1"
	if got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestBuildSANs_Empty(t *testing.T) {
	csr := &x509.CertificateRequest{}
	got := buildSANs(csr)
	if got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}
