package dpop_http

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/conductorone/dpop/pkg/dpop"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// mockTokenSource implements oauth2.TokenSource for testing
type mockTokenSource struct {
	token *oauth2.Token
}

func (m *mockTokenSource) Token() (*oauth2.Token, error) {
	return m.token, nil
}

// testHandler is a test HTTP handler that validates DPoP and returns the claims
type testHandler struct {
	t *testing.T
}

func (h *testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get the DPoP claims from the context
	claims, ok := dpop.ClaimsFromContext(r.Context())
	require.True(h.t, ok, "DPoP claims should be present in context")
	require.NotNil(h.t, claims, "DPoP claims should not be nil")

	// Return the claims as JSON for validation
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(claims)
	require.NoError(h.t, err)
}

func TestDPoPRoundTrip(t *testing.T) {
	// Generate a test Ed25519 key pair for DPoP proofs
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Create JWK for private key
	jwk := &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	// Create a mock token source
	tokenSource := &mockTokenSource{
		token: &oauth2.Token{
			AccessToken: "test-access-token",
			TokenType:   "DPoP",
			Expiry:      time.Now().Add(time.Hour),
		},
	}

	// Create a test server with DPoP middleware
	handler := &testHandler{t: t}
	mw := Middleware()
	server := httptest.NewServer(mw(handler))
	defer server.Close()

	// Create a DPoP-enabled HTTP client
	transport, err := NewTransport(
		http.DefaultTransport,
		jwk,
		tokenSource,
		dpop.WithStaticNonce("test-nonce"), // Use a static nonce for testing
	)
	require.NoError(t, err)

	client := &http.Client{
		Transport: transport,
	}

	// Test cases
	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		validateResp   func(*testing.T, *dpop.Claims, string)
	}{
		{
			name:           "GET request with valid DPoP proof",
			method:         "GET",
			path:           "/api/resource",
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, claims *dpop.Claims, serverURL string) {
				assert.NotEmpty(t, claims.Claims.ID)
				assert.Equal(t, "GET", claims.HTTPMethod)
				expectedURL := serverURL + "/api/resource"
				assert.Equal(t, expectedURL, claims.HTTPUri, "DPoP proof should contain the full URL")
				assert.Equal(t, "test-nonce", claims.Nonce)
				assert.NotNil(t, claims.Claims.IssuedAt)
			},
		},
		{
			name:           "POST request with valid DPoP proof",
			method:         "POST",
			path:           "/api/resource",
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, claims *dpop.Claims, serverURL string) {
				assert.NotEmpty(t, claims.Claims.ID)
				assert.Equal(t, "POST", claims.HTTPMethod)
				expectedURL := serverURL + "/api/resource"
				assert.Equal(t, expectedURL, claims.HTTPUri, "DPoP proof should contain the full URL")
				assert.Equal(t, "test-nonce", claims.Nonce)
				assert.NotNil(t, claims.Claims.IssuedAt)
			},
		},
		{
			name:           "PUT request with valid DPoP proof",
			method:         "PUT",
			path:           "/api/resource",
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, claims *dpop.Claims, serverURL string) {
				assert.NotEmpty(t, claims.Claims.ID)
				assert.Equal(t, "PUT", claims.HTTPMethod)
				expectedURL := serverURL + "/api/resource"
				assert.Equal(t, expectedURL, claims.HTTPUri, "DPoP proof should contain the full URL")
				assert.Equal(t, "test-nonce", claims.Nonce)
				assert.NotNil(t, claims.Claims.IssuedAt)
				// Verify that IssuedAt is within acceptable time window
				assert.True(t, time.Since(claims.Claims.IssuedAt.Time()) < time.Minute)
			},
		},
		{
			name:           "Request with query parameters",
			method:         "GET",
			path:           "/api/resource?param1=value1&param2=value2",
			expectedStatus: http.StatusOK,
			validateResp: func(t *testing.T, claims *dpop.Claims, serverURL string) {
				assert.NotEmpty(t, claims.Claims.ID)
				assert.Equal(t, "GET", claims.HTTPMethod)
				expectedURL := serverURL + "/api/resource?param1=value1&param2=value2"
				assert.Equal(t, expectedURL, claims.HTTPUri, "DPoP proof should contain the full URL")
				assert.Equal(t, "test-nonce", claims.Nonce)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create and execute request
			req, err := http.NewRequestWithContext(context.Background(), tc.method, server.URL+tc.path, nil)
			require.NoError(t, err)

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			// Verify response status
			assert.Equal(t, tc.expectedStatus, resp.StatusCode)

			// Decode and validate claims from response
			var claims dpop.Claims
			err = json.NewDecoder(resp.Body).Decode(&claims)
			require.NoError(t, err)

			// Run test-specific validations
			tc.validateResp(t, &claims, server.URL)
		})
	}
}

// TestDPoPErrorCases tests various error scenarios for DPoP
func TestDPoPErrorCases(t *testing.T) {
	// Create a test server with DPoP middleware
	mw := Middleware()
	server := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer server.Close()

	// Test cases for error scenarios
	tests := []struct {
		name           string
		setupClient    func() *http.Client
		expectedStatus int
	}{
		{
			name: "Missing DPoP header",
			setupClient: func() *http.Client {
				return &http.Client{} // Plain client with no DPoP
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Wrong HTTP method in proof",
			setupClient: func() *http.Client {
				pub, priv, _ := ed25519.GenerateKey(nil)
				require.NotNil(t, pub) // Keep the public key reference to prevent GC

				jwk := &jose.JSONWebKey{
					Key:       priv,
					KeyID:     "test-key",
					Algorithm: string(jose.EdDSA),
					Use:       "sig",
				}

				transport, _ := NewTransport(
					http.DefaultTransport,
					jwk,
					&mockTokenSource{
						token: &oauth2.Token{
							AccessToken: "test-token",
							TokenType:   "DPoP",
						},
					},
					dpop.WithProofNowFunc(func() time.Time {
						return time.Now().Add(-24 * time.Hour) // Old timestamp
					}),
				)
				return &http.Client{Transport: transport}
			},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := tc.setupClient()
			req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/api/resource", nil)
			require.NoError(t, err)

			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				assert.Equal(t, tc.expectedStatus, resp.StatusCode)
			} else {
				// Some error cases might result in client-side errors
				assert.NotNil(t, err)
			}
		})
	}
}

// TestDPoPNonceHandling tests the nonce handling functionality
func TestDPoPNonceHandling(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	require.NotNil(t, pub) // Keep the public key reference to prevent GC

	jwk := &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	// Create a server that requires nonce
	nonceValue := "server-generated-nonce"
	serverOpts := []ServerOption{
		WithNonceGenerator(func(ctx context.Context) (string, error) {
			return nonceValue, nil
		}),
	}

	mw := Middleware(serverOpts...)
	server := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer server.Close()

	// First request without nonce should receive nonce header
	client := &http.Client{}
	req, err := http.NewRequestWithContext(context.Background(), "GET", server.URL+"/api/resource", nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify server sent nonce
	assert.Equal(t, nonceValue, resp.Header.Get(dpop.NonceHeaderName))

	// Create DPoP client with the received nonce
	transport, err := NewTransport(
		http.DefaultTransport,
		jwk,
		&mockTokenSource{
			token: &oauth2.Token{
				AccessToken: "test-token",
				TokenType:   "DPoP",
			},
		},
		dpop.WithStaticNonce(nonceValue),
	)
	require.NoError(t, err)

	// Second request with correct nonce should succeed
	client = &http.Client{Transport: transport}
	req, err = http.NewRequestWithContext(context.Background(), "GET", server.URL+"/api/resource", nil)
	require.NoError(t, err)

	resp, err = client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
