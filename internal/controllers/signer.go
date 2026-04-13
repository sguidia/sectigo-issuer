/*
Copyright 2023 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"

	issuerapi "github.com/cert-manager/issuer-lib/api/v1alpha1"
	"github.com/cert-manager/issuer-lib/controllers"
	"github.com/cert-manager/issuer-lib/controllers/signer"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sectigoissuerapi "github.com/sguidia/sectigo-issuer/api/v1alpha1"
	"github.com/sguidia/sectigo-issuer/internal/sectigo"
)

const (
	// annotationSSLID is stored on the CertificateRequest to persist the
	// Sectigo SSL ID between Sign() retries while the certificate is being
	// issued asynchronously.
	annotationSSLID = "sectigo.opensource.io/ssl-id"

	// secretKeyClientID and secretKeyClientSecret are the expected keys
	// inside the Kubernetes Secret referenced by AuthSecretName.
	secretKeyClientID     = "client-id"
	secretKeyClientSecret = "client-secret"
)

// Issuer bridges cert-manager with the Sectigo Certificate Manager API.
// It implements the issuer-lib Sign and Check callbacks.
type Issuer struct {
	ClusterResourceNamespace string

	client client.Client
}

// +kubebuilder:rbac:groups=sectigo.opensource.io,resources=sectigoclusterissuers;sectigoissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=sectigo.opensource.io,resources=sectigoclusterissuers/status;sectigoissuers/status,verbs=patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/status,verbs=patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,verbs=sign,resourceNames=sectigoclusterissuers.sectigo.opensource.io/*;sectigoissuers.sectigo.opensource.io/*

func (s Issuer) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	s.client = mgr.GetClient()

	return (&controllers.CombinedController{
		IssuerTypes:        []issuerapi.Issuer{&sectigoissuerapi.SectigoIssuer{}},
		ClusterIssuerTypes: []issuerapi.Issuer{&sectigoissuerapi.SectigoClusterIssuer{}},

		FieldOwner:       "sectigoissuer.cert-manager.io",
		MaxRetryDuration: 1 * time.Minute,

		Sign:          s.Sign,
		Check:         s.Check,
		EventRecorder: mgr.GetEventRecorder("sectigoissuer.cert-manager.io"),
	}).SetupWithManager(ctx, mgr)
}

// getIssuerDetails extracts the spec and the namespace where the auth secret
// should be looked up.
func (o *Issuer) getIssuerDetails(issuerObject issuerapi.Issuer) (*sectigoissuerapi.SectigoIssuerSpec, string, error) {
	switch t := issuerObject.(type) {
	case *sectigoissuerapi.SectigoIssuer:
		return &t.Spec, issuerObject.GetNamespace(), nil
	case *sectigoissuerapi.SectigoClusterIssuer:
		return &t.Spec, o.ClusterResourceNamespace, nil
	default:
		return nil, "", signer.PermanentError{
			Err: fmt.Errorf("unexpected issuer type: %t", issuerObject),
		}
	}
}

// getSecretData fetches the Kubernetes Secret referenced by the issuer spec.
func (o *Issuer) getSecretData(ctx context.Context, issuerSpec *sectigoissuerapi.SectigoIssuerSpec, namespace string) (map[string][]byte, error) {
	secretName := types.NamespacedName{
		Namespace: namespace,
		Name:      issuerSpec.AuthSecretName,
	}

	var secret corev1.Secret
	if err := o.client.Get(ctx, secretName, &secret); err != nil {
		return nil, fmt.Errorf("failed to get Secret %s: %w", secretName, err)
	}

	return secret.Data, nil
}

// clientFromSpecAndSecret constructs a Sectigo API client from the issuer spec
// and the raw secret data. It returns a PermanentError when the secret does
// not contain the required keys.
func clientFromSpecAndSecret(spec *sectigoissuerapi.SectigoIssuerSpec, secretData map[string][]byte) (*sectigo.Client, error) {
	clientID, ok := secretData[secretKeyClientID]
	if !ok || len(clientID) == 0 {
		return nil, signer.PermanentError{
			Err: fmt.Errorf("secret missing required key %q", secretKeyClientID),
		}
	}

	clientSecret, ok := secretData[secretKeyClientSecret]
	if !ok || len(clientSecret) == 0 {
		return nil, signer.PermanentError{
			Err: fmt.Errorf("secret missing required key %q", secretKeyClientSecret),
		}
	}

	return sectigo.NewClient(
		spec.URL,
		spec.TokenURL,
		string(clientID),
		string(clientSecret),
	), nil
}

// Check validates that the issuer is properly configured and that a Sectigo
// client can be constructed from the spec and secret data. Certificate
// requests will not be processed until this check passes.
func (o *Issuer) Check(ctx context.Context, issuerObject issuerapi.Issuer) error {
	issuerSpec, namespace, err := o.getIssuerDetails(issuerObject)
	if err != nil {
		return err
	}

	secretData, err := o.getSecretData(ctx, issuerSpec, namespace)
	if err != nil {
		return err
	}

	// Validate that we can construct a client (i.e. required secret keys exist).
	if _, err := clientFromSpecAndSecret(issuerSpec, secretData); err != nil {
		return err
	}

	return nil
}

// Sign issues a certificate via the Sectigo API for the given
// CertificateRequest. The flow is asynchronous:
//
//  1. On the first call (no ssl-id annotation), the CSR is submitted to
//     Sectigo via Enroll(). The returned SSL ID is stored in an annotation
//     so subsequent retries can skip enrollment.
//
//  2. On subsequent calls (ssl-id annotation present), Collect() is called
//     to check whether the certificate is ready. If Sectigo returns a
//     NotReadyError, Sign returns a PendingError so issuer-lib retries later.
//
//  3. Once Collect() succeeds, the PEM chain is returned in a PEMBundle.
func (o *Issuer) Sign(ctx context.Context, cr signer.CertificateRequestObject, issuerObject issuerapi.Issuer) (signer.PEMBundle, error) {
	issuerSpec, namespace, err := o.getIssuerDetails(issuerObject)
	if err != nil {
		return signer.PEMBundle{}, signer.IssuerError{Err: err}
	}

	secretData, err := o.getSecretData(ctx, issuerSpec, namespace)
	if err != nil {
		return signer.PEMBundle{}, signer.IssuerError{Err: err}
	}

	sectigoClient, err := clientFromSpecAndSecret(issuerSpec, secretData)
	if err != nil {
		return signer.PEMBundle{}, signer.IssuerError{Err: err}
	}

	// Check if we already have a Sectigo SSL ID from a previous attempt.
	annotations := cr.GetAnnotations()
	sslIDStr := ""
	if annotations != nil {
		sslIDStr = annotations[annotationSSLID]
	}

	if sslIDStr != "" {
		// We have already enrolled -- try to collect the certificate.
		sslID, err := strconv.Atoi(sslIDStr)
		if err != nil {
			return signer.PEMBundle{}, signer.PermanentError{
				Err: fmt.Errorf("invalid %s annotation value %q: %w", annotationSSLID, sslIDStr, err),
			}
		}

		return collectCertificate(ctx, sectigoClient, sslID)
	}

	// First call -- enroll the CSR with Sectigo.
	certDetails, err := cr.GetCertificateDetails()
	if err != nil {
		return signer.PEMBundle{}, signer.PermanentError{
			Err: fmt.Errorf("failed to get certificate details: %w", err),
		}
	}

	csrPEM := certDetails.CSR
	csrDER, err := extractCSRFromPEM(csrPEM)
	if err != nil {
		return signer.PEMBundle{}, signer.PermanentError{
			Err: fmt.Errorf("failed to parse CSR PEM: %w", err),
		}
	}

	parsedCSR, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return signer.PEMBundle{}, signer.PermanentError{
			Err: fmt.Errorf("failed to parse CSR DER: %w", err),
		}
	}

	// Build the subject alternative names list for the Sectigo API.
	sans := buildSANs(parsedCSR)

	enrollReq := sectigo.EnrollRequest{
		OrgID:    issuerSpec.OrganizationID,
		CSR:      string(csrPEM),
		CertType: issuerSpec.CertificateType,
		Term:     issuerSpec.Term,
	}
	if sans != "" {
		enrollReq.SubjAltNames = sans
	}

	enrollResp, err := sectigoClient.Enroll(ctx, enrollReq)
	if err != nil {
		return signer.PEMBundle{}, fmt.Errorf("sectigo enroll failed: %w", err)
	}

	// Store the SSL ID in an annotation for subsequent retries.
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[annotationSSLID] = strconv.Itoa(enrollResp.SSLID)
	cr.SetAnnotations(annotations)

	// Try to collect immediately -- the certificate might already be ready.
	return collectCertificate(ctx, sectigoClient, enrollResp.SSLID)
}

// collectCertificate attempts to retrieve the issued certificate from Sectigo.
// If the certificate is not yet ready, it returns a PendingError to trigger
// a retry by issuer-lib.
func collectCertificate(ctx context.Context, c *sectigo.Client, sslID int) (signer.PEMBundle, error) {
	pemData, err := c.Collect(ctx, sslID)
	if err != nil {
		if sectigo.IsNotReadyError(err) {
			return signer.PEMBundle{}, signer.PendingError{
				Err:          fmt.Errorf("certificate sslId=%d not ready yet, will retry", sslID),
				RequeueAfter: 10 * time.Second,
			}
		}
		return signer.PEMBundle{}, fmt.Errorf("sectigo collect failed for sslId=%d: %w", sslID, err)
	}

	return signer.PEMBundle{
		ChainPEM: pemData,
	}, nil
}

// extractCSRFromPEM decodes the first PEM block from the given data and
// returns the raw DER bytes. Returns an error if no CERTIFICATE REQUEST
// block is found.
func extractCSRFromPEM(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found")
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("unexpected PEM block type %q, expected CERTIFICATE REQUEST", block.Type)
	}
	return block.Bytes, nil
}

// buildSANs extracts DNS names and IP addresses from the parsed CSR and
// returns them as a comma-separated string suitable for the Sectigo API
// SubjAltNames field.
func buildSANs(csr *x509.CertificateRequest) string {
	var sans []string
	for _, dns := range csr.DNSNames {
		sans = append(sans, dns)
	}
	for _, ip := range csr.IPAddresses {
		sans = append(sans, ip.String())
	}
	return strings.Join(sans, ",")
}
