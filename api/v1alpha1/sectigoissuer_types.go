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

package v1alpha1

import (
	"github.com/cert-manager/issuer-lib/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].status"
// +kubebuilder:printcolumn:name="Reason",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].reason"
// +kubebuilder:printcolumn:name="Message",type="string",JSONPath=".status.conditions[?(@.type==\"Ready\")].message"
// +kubebuilder:printcolumn:name="LastTransition",type="string",type="date",JSONPath=".status.conditions[?(@.type==\"Ready\")].lastTransitionTime"
// +kubebuilder:printcolumn:name="ObservedGeneration",type="integer",JSONPath=".status.conditions[?(@.type==\"Ready\")].observedGeneration"
// +kubebuilder:printcolumn:name="Generation",type="integer",JSONPath=".metadata.generation"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// SectigoIssuer is the Schema for the sectigoissuers API.
type SectigoIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SectigoIssuerSpec     `json:"spec,omitempty"`
	Status v1alpha1.IssuerStatus `json:"status,omitempty"`
}

// GetSpec returns the issuer spec for generic access by the controller.
func (vi *SectigoIssuer) GetSpec() *SectigoIssuerSpec {
	return &vi.Spec
}

// SectigoIssuerSpec defines the desired state of SectigoIssuer and SectigoClusterIssuer.
type SectigoIssuerSpec struct {
	// URL is the base URL of the Sectigo API.
	// +kubebuilder:default="https://admin.enterprise.sectigo.com/api"
	URL string `json:"url"`

	// CustomerURI is the Sectigo customer URI identifier.
	CustomerURI string `json:"customerUri"`

	// AuthSecretName is the name of a Secret containing client-id and client-secret keys.
	// For a SectigoClusterIssuer, the Secret is looked up in the configured
	// cluster resource namespace (defaults to the controller's namespace).
	AuthSecretName string `json:"authSecretName"`

	// TokenURL is the OAuth2 token endpoint.
	// +kubebuilder:default="https://auth.sso.sectigo.com/auth/realms/apiclients/protocol/openid-connect/token"
	// +optional
	TokenURL string `json:"tokenUrl,omitempty"`

	// OrganizationID is the Sectigo organization ID for certificate requests.
	OrganizationID int `json:"organizationId"`

	// CertificateType is the Sectigo certificate profile ID.
	// +kubebuilder:default=31466
	CertificateType int `json:"certificateType"`

	// Term is the certificate validity in days.
	// +kubebuilder:default=365
	Term int `json:"term"`
}

func (vi *SectigoIssuer) GetConditions() []metav1.Condition {
	return vi.Status.Conditions
}

// GetIssuerTypeIdentifier returns a string that uniquely identifies the
// issuer type. This should be a constant across all instances of this
// issuer type. This string is used as a prefix when determining the
// issuer type for a Kubernetes CertificateSigningRequest resource based
// on the issuerName field. The value should be formatted as follows:
// "<issuer resource (plural)>.<issuer group>". For example, the value
// "simpleclusterissuers.issuer.cert-manager.io" will match all CSRs
// with an issuerName set to eg. "simpleclusterissuers.issuer.cert-manager.io/issuer1".
func (vi *SectigoIssuer) GetIssuerTypeIdentifier() string {
	// ACTION REQUIRED: Change this to a unique string that identifies your issuer
	return "sectigoissuers.sectigo.opensource.io"
}

// issuer-lib requires that we implement the Issuer interface
// so that it can interact with our Issuer resource.
var _ v1alpha1.Issuer = &SectigoIssuer{}

// +kubebuilder:object:root=true

// SectigoIssuerList contains a list of SectigoIssuer.
type SectigoIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SectigoIssuer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SectigoIssuer{}, &SectigoIssuerList{})
}
