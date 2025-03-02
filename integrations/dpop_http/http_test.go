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
	mw := Middleware(WithValidationOptions(dpop.WithNonceValidator(func(ctx context.Context, nonce string) error {
		require.Equal(t, "test-nonce", nonce)
		return nil
	})), WithErrorHandler(func(rw http.ResponseWriter, r *http.Request, err error) {
		t.Logf("Error: %v", err)
	}))
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
			name: "Not a DPoP request",
			setupClient: func() *http.Client {
				return &http.Client{} // Plain client with no DPoP
			},
			expectedStatus: http.StatusOK, // Should pass through without DPoP validation
		},
		{
			name: "Included DPoP header but not a DPoP access token",
			setupClient: func() *http.Client {
				pub, priv, _ := ed25519.GenerateKey(nil)
				require.NotNil(t, pub)

				jwk := &jose.JSONWebKey{
					Key:       priv,
					KeyID:     "test-key",
					Algorithm: string(jose.EdDSA),
					Use:       "sig",
				}

				// Create a custom transport that adds DPoP header but uses Bearer token
				return &http.Client{
					Transport: &customTransport{
						base:      http.DefaultTransport,
						jwk:       jwk,
						token:     "test-token",
						tokenType: "Bearer", // Not DPoP
					},
				}
			},
			expectedStatus: http.StatusUnauthorized, // Should fail with invalid auth scheme
		},
		{
			name: "Access token is DPoP scheme but no proof provided",
			setupClient: func() *http.Client {
				// Create a client that sends DPoP token type but no DPoP header
				return &http.Client{
					Transport: &customTransport{
						base:      http.DefaultTransport,
						token:     "test-token",
						tokenType: "DPoP",
						skipDPoP:  true, // Don't add DPoP header
					},
				}
			},
			expectedStatus: http.StatusUnauthorized, // Should fail with missing DPoP header
		},
		{
			name: "Invalid proof (wrong HTTP method)",
			setupClient: func() *http.Client {
				pub, priv, _ := ed25519.GenerateKey(nil)
				require.NotNil(t, pub)

				jwk := &jose.JSONWebKey{
					Key:       priv,
					KeyID:     "test-key",
					Algorithm: string(jose.EdDSA),
					Use:       "sig",
				}

				// Create a custom transport that adds DPoP header with wrong method
				return &http.Client{
					Transport: &customTransport{
						base:         http.DefaultTransport,
						jwk:          jwk,
						token:        "test-token",
						tokenType:    "DPoP",
						customMethod: "POST", // Wrong method (will be GET)
					},
				}
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Invalid proof (wrong endpoint)",
			setupClient: func() *http.Client {
				pub, priv, _ := ed25519.GenerateKey(nil)
				require.NotNil(t, pub)

				jwk := &jose.JSONWebKey{
					Key:       priv,
					KeyID:     "test-key",
					Algorithm: string(jose.EdDSA),
					Use:       "sig",
				}

				// Create a custom transport that adds DPoP header with wrong URL
				return &http.Client{
					Transport: &customTransport{
						base:      http.DefaultTransport,
						jwk:       jwk,
						token:     "test-token",
						tokenType: "DPoP",
						customURL: "https://wrong-endpoint.com/resource", // Wrong URL
					},
				}
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "Old proof",
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
		{
			name: "Invalid token binding",
			setupClient: func() *http.Client {
				pub, priv, _ := ed25519.GenerateKey(nil)
				require.NotNil(t, pub)

				jwk := &jose.JSONWebKey{
					Key:       priv,
					KeyID:     "test-key",
					Algorithm: string(jose.EdDSA),
					Use:       "sig",
				}

				// Create a custom transport with mismatched token binding
				return &http.Client{
					Transport: &customTransport{
						base:       http.DefaultTransport,
						jwk:        jwk,
						token:      "test-token",
						tokenType:  "DPoP",
						boundToken: "different-token", // Mismatch with the token in Authorization header
					},
				}
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
		// Add validation options to validate the nonce
		WithValidationOptions(dpop.WithNonceValidator(func(ctx context.Context, nonce string) error {
			if nonce != nonceValue {
				return dpop.ErrInvalidNonce
			}
			return nil
		})),
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

	// Create a custom transport with the received nonce
	customTransport := &customTransport{
		base:      http.DefaultTransport,
		jwk:       jwk,
		token:     "test-token",
		tokenType: "DPoP",
		nonce:     nonceValue,
	}

	// Second request with correct nonce should succeed
	client = &http.Client{Transport: customTransport}
	req, err = http.NewRequestWithContext(context.Background(), "GET", server.URL+"/api/resource", nil)
	require.NoError(t, err)

	resp, err = client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// customTransport is a test helper that allows fine-grained control over headers
type customTransport struct {
	base         http.RoundTripper
	jwk          *jose.JSONWebKey
	token        string
	tokenType    string
	skipDPoP     bool
	customMethod string
	customURL    string
	boundToken   string
	nonce        string
}

func (t *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Set Authorization header
	if t.token != "" {
		req.Header.Set("Authorization", t.tokenType+" "+t.token)
	}

	// Add DPoP header if needed
	if !t.skipDPoP && t.jwk != nil {
		proofer, err := dpop.NewProofer(t.jwk)
		if err != nil {
			return nil, err
		}

		// Determine which method and URL to use for the proof
		method := req.Method
		if t.customMethod != "" {
			method = t.customMethod
		}

		url := req.URL.String()
		if t.customURL != "" {
			url = t.customURL
		}

		// Create proof options
		var opts []dpop.ProofOption
		if t.boundToken != "" {
			opts = append(opts, dpop.WithAccessToken(t.boundToken))
		} else if t.token != "" && t.tokenType == "DPoP" {
			opts = append(opts, dpop.WithAccessToken(t.token))
		}

		// Add nonce if provided
		if t.nonce != "" {
			opts = append(opts, dpop.WithStaticNonce(t.nonce))
		}

		// Create the proof with potentially incorrect method/URL
		proof, err := proofer.CreateProof(req.Context(), method, url, opts...)
		if err != nil {
			return nil, err
		}
		req.Header.Set(dpop.HeaderName, proof)
	}

	// Use the base transport for the actual request
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}
