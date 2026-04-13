package sectigo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Client is an HTTP client for the Sectigo Certificate Manager API.
// It transparently handles OAuth2 client-credentials token acquisition
// and renewal via golang.org/x/oauth2.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new Sectigo API client. It configures an OAuth2
// client-credentials flow that automatically fetches and refreshes the
// access token.
//
//   - baseURL:      Sectigo API base URL (e.g. "https://cert-manager.com/api")
//   - tokenURL:     OAuth2 token endpoint
//   - clientID:     OAuth2 client ID
//   - clientSecret: OAuth2 client secret
func NewClient(baseURL, tokenURL, clientID, clientSecret string) *Client {
	cfg := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL,
	}
	return &Client{
		baseURL:    baseURL,
		httpClient: cfg.Client(context.Background()),
	}
}

// NewClientWithHTTP creates a client with a caller-supplied *http.Client.
// This is useful for testing, where the caller can inject a client that
// points at an httptest.Server.
func NewClientWithHTTP(baseURL string, httpClient *http.Client) *Client {
	return &Client{
		baseURL:    baseURL,
		httpClient: httpClient,
	}
}

// doRequest performs an HTTP request and decodes the JSON response body into
// dest. It returns an *APIError for non-2xx status codes.
func (c *Client) doRequest(ctx context.Context, method, path string, body io.Reader, dest interface{}) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{
			StatusCode: resp.StatusCode,
			Body:       string(respBody),
		}
	}

	if dest != nil {
		if err := json.Unmarshal(respBody, dest); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}

	return nil
}

// doRequestRaw performs an HTTP request and returns the raw response body
// as bytes. It returns an *APIError for non-2xx status codes.
func (c *Client) doRequestRaw(ctx context.Context, method, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
	}

	return body, nil
}

// tokenSource returns the underlying OAuth2 token source. This is exposed
// so that the health check can verify that credentials are valid by obtaining
// a token.
func (c *Client) tokenSource() oauth2.TokenSource {
	// The http.Client created by clientcredentials.Config wraps its Transport
	// with an oauth2.Transport that holds the TokenSource. If the client was
	// created with NewClientWithHTTP (tests), there is no oauth2.Transport.
	if t, ok := c.httpClient.Transport.(*oauth2.Transport); ok {
		return t.Source
	}
	return nil
}
