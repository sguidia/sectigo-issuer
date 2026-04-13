# Sectigo Issuer for cert-manager

A Kubernetes [cert-manager](https://cert-manager.io/) external issuer that automates TLS certificate lifecycle using the [Sectigo Certificate Manager](https://www.sectigo.com/certificate-manager) (SCM) REST API with OAuth2 authentication.

## Prerequisites

- Kubernetes 1.25+
- cert-manager v1.12+
- Sectigo Certificate Manager account with Web API access enabled
- OAuth2 client credentials (client ID and client secret) from Sectigo

## Quick Start

### 1. Install the controller

```bash
helm install sectigo-issuer oci://ghcr.io/guidise/sectigo-issuer/charts/sectigo-issuer \
  --namespace sectigo-issuer-system \
  --create-namespace
```

### 2. Create a Secret with your Sectigo credentials

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: sectigo-credentials
  namespace: sectigo-issuer-system
type: Opaque
stringData:
  client-id: "your-oauth2-client-id"
  client-secret: "your-oauth2-client-secret"
```

### 3. Create a SectigoClusterIssuer

```yaml
apiVersion: sectigo.opensource.io/v1alpha1
kind: SectigoClusterIssuer
metadata:
  name: sectigo
spec:
  customerUri: "your-customer-uri"
  authSecretName: sectigo-credentials
  organizationId: 12345
  certificateType: 31466
  term: 365
```

### 4. Request a Certificate

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: my-app-tls
  namespace: default
spec:
  secretName: my-app-tls
  issuerRef:
    name: sectigo
    kind: SectigoClusterIssuer
    group: sectigo.opensource.io
  dnsNames:
    - my-app.example.com
  duration: 8760h   # 365 days
  renewBefore: 720h # 30 days
```

cert-manager will automatically request, collect, and renew the certificate.

## Configuration Reference

| Field | Type | Default | Required | Description |
|-------|------|---------|----------|-------------|
| `url` | string | `https://admin.enterprise.sectigo.com/api` | No | Sectigo API base URL |
| `customerUri` | string | | Yes | Your Sectigo customer URI identifier |
| `authSecretName` | string | | Yes | Name of the Secret containing `client-id` and `client-secret` keys |
| `tokenUrl` | string | `https://auth.sso.sectigo.com/auth/realms/apiclients/protocol/openid-connect/token` | No | OAuth2 token endpoint |
| `organizationId` | int | | Yes | Sectigo organization ID |
| `certificateType` | int | `31466` | No | Sectigo certificate profile ID |
| `term` | int | `365` | No | Certificate validity in days |

The Secret referenced by `authSecretName` must contain two keys:

- `client-id` -- OAuth2 client ID
- `client-secret` -- OAuth2 client secret

For a namespaced `SectigoIssuer`, the Secret must be in the same namespace as the issuer. For a `SectigoClusterIssuer`, the Secret must be in the controller's namespace (default: `sectigo-issuer-system`).

## Finding Your Sectigo Configuration

Use the Sectigo API to discover your organization ID and available certificate types.

### Get an access token

```bash
TOKEN=$(curl -s -X POST \
  "https://auth.sso.sectigo.com/auth/realms/apiclients/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  | jq -r '.access_token')
```

### List organizations

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://admin.enterprise.sectigo.com/api/organization/v1" \
  -H "customerUri: YOUR_CUSTOMER_URI" \
  | jq '.[] | {id, name}'
```

### List SSL certificate types

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://admin.enterprise.sectigo.com/api/ssl/v1/types" \
  -H "customerUri: YOUR_CUSTOMER_URI" \
  | jq '.[] | {id, name, term}'
```

Use the `id` from the certificate types response as the `certificateType` value in your issuer spec.

## How It Works

1. A cert-manager `Certificate` resource is created referencing a `SectigoClusterIssuer` (or `SectigoIssuer`).
2. cert-manager generates a private key and a CSR, then creates a `CertificateRequest`.
3. The sectigo-issuer controller detects the `CertificateRequest` and validates the issuer configuration.
4. The controller authenticates to Sectigo using OAuth2 client credentials.
5. The CSR is submitted to the Sectigo enrollment API (`POST /ssl/v1/enroll`). The returned SSL ID is stored as an annotation on the `CertificateRequest`.
6. The controller polls the Sectigo collect endpoint (`GET /ssl/v1/collect/{sslId}/pem`) until the certificate is issued.
7. The signed PEM certificate chain is returned to cert-manager.
8. cert-manager stores the certificate and key in the target Kubernetes Secret as a TLS secret.

## Limitations

- **Domain Control Validation (DCV) must be pre-configured.** Sectigo requires domain ownership to be validated before certificates can be issued. DCV must be completed out of band (e.g., DNS CNAME or HTTP file) before using this issuer.
- **Public SSL certificates only.** This issuer uses the `/ssl/v1/enroll` endpoint designed for public SSL/TLS certificates.
- **No ACME support.** This issuer uses the Sectigo REST API, not the ACME protocol. If you need ACME-based issuance, use cert-manager's built-in ACME issuer instead.

## Contributing

### Build

```bash
make build
```

### Run tests

```bash
make test
```

### Run locally against a cluster

```bash
make run
```

### Build the Docker image

```bash
make docker-build IMG=sectigo-issuer:dev
```

### Run end-to-end tests

```bash
make kind-cluster deploy-cert-manager
make docker-build kind-load deploy e2e
```

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.
