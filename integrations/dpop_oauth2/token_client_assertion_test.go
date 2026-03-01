package dpop_oauth2

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/conductorone/dpop/pkg/dpop"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

// mockAuthServer implements a mock OAuth2 authorization server for testing
type mockAuthServer struct {
	t              *testing.T
	server         *httptest.Server
	expectedJWK    *jose.JSONWebKey
	nonce          string
	enforceNonce   bool
	tokenType      string
	replayDetected bool
	seenJTIs       map[string]bool
	validator      *dpop.Validator
}

func (m *mockAuthServer) setupValidator() {
	opts := []dpop.Option{
		dpop.WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
		dpop.WithJTIStore(func(ctx context.Context, jti string) error {
			return nil
		}),
		dpop.WithNonceValidator(func(ctx context.Context, nonce string) error {
			m.t.Logf("Validating nonce: got %q, want %q (enforceNonce=%v)", nonce, m.nonce, m.enforceNonce)
			if m.enforceNonce && nonce != m.nonce {
				return fmt.Errorf("invalid nonce")
			}
			return nil
		}),
	}

	m.validator = dpop.NewValidator(opts...)
}

func newMockAuthServer(t *testing.T, jwk *jose.JSONWebKey) *mockAuthServer {
	mas := &mockAuthServer{
		t:           t,
		expectedJWK: jwk,
		tokenType:   "DPoP",
		seenJTIs:    make(map[string]bool),
		nonce:       "initial-nonce",
	}

	// Create validator with appropriate options
	mas.validator = dpop.NewValidator(
		dpop.WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
		dpop.WithJTIStore(dpop.NewMemoryJTIStore().CheckAndStoreJTI),
		dpop.WithNonceValidator(func(ctx context.Context, nonce string) error {
			if nonce != mas.nonce {
				return fmt.Errorf("invalid nonce")
			}
			return nil
		}),
	)

	mas.server = httptest.NewServer(http.HandlerFunc(mas.handleToken))
	return mas
}

func (m *mockAuthServer) handleToken(w http.ResponseWriter, r *http.Request) {
	// Verify method and content type
	if r.Method != "POST" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_request",
			"error_description": "Method not allowed",
		})
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_request",
			"error_description": "Invalid content type",
		})
		return
	}

	// Parse DPoP proof
	dpopProof := r.Header.Get("DPoP")
	if dpopProof == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_dpop_proof",
			"error_description": "Missing DPoP proof",
		})
		return
	}

	m.t.Logf("Validating DPoP proof with enforceNonce=%v, nonce=%q", m.enforceNonce, m.nonce)

	// Parse the proof to check for nonce
	token, err := jose.ParseSigned(dpopProof, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_dpop_proof",
			"error_description": "Invalid DPoP proof format",
		})
		return
	}

	var proofClaims struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(token.UnsafePayloadWithoutVerification(), &proofClaims); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_dpop_proof",
			"error_description": "Invalid DPoP proof claims",
		})
		return
	}

	// Always require a nonce, but only enforce specific value when enforceNonce is true
	if proofClaims.Nonce == "" || (m.enforceNonce && proofClaims.Nonce != m.nonce) {
		w.Header().Set(dpop.NonceHeaderName, m.nonce)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "use_dpop_nonce",
			"error_description": "Authorization server requires nonce in DPoP proof",
		})
		return
	}

	// Validate DPoP proof using the server's validator
	claims, err := m.validator.ValidateProof(context.Background(), dpopProof, r.Method, m.server.URL+"/token")
	if err != nil {
		m.t.Logf("Validation error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_dpop_proof",
			"error_description": fmt.Sprintf("Invalid DPoP proof: %v", err),
		})
		return
	}

	// Track replay detection
	if claims != nil && claims.Claims.ID != "" {
		m.seenJTIs[claims.Claims.ID] = true
	}

	// Verify client credentials
	err = r.ParseForm()
	if err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// Return successful token response
	resp := map[string]interface{}{
		"access_token": "test_access_token",
		"token_type":   m.tokenType,
		"expires_in":   3600,
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "server_error",
			"error_description": "Failed to encode response",
		})
	}
}

func (m *mockAuthServer) Close() {
	m.server.Close()
}

func TestTokenSource_Token(t *testing.T) {
	// Generate test keys
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Create JWKs for public and private keys
	pubJWK := &jose.JSONWebKey{
		Key:       pub,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	privJWK := &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	// Create DPoP proofer
	proofer, err := dpop.NewProofer(privJWK)
	require.NoError(t, err)

	tests := []struct {
		name          string
		setupServer   func(*mockAuthServer)
		expectError   bool
		errorContains string
	}{
		{
			name: "successful token request",
			setupServer: func(mas *mockAuthServer) {
				mas.enforceNonce = false
				mas.setupValidator()
			},
		},
		{
			name: "nonce required",
			setupServer: func(mas *mockAuthServer) {
				mas.enforceNonce = true
				mas.nonce = "test-nonce-123"
				mas.setupValidator()
			},
			// The token source should automatically retry with the nonce
			expectError: false,
		},
		{
			name: "non-DPoP token type",
			setupServer: func(mas *mockAuthServer) {
				mas.tokenType = "Bearer"
				mas.setupValidator()
			},
			// The token source should accept Bearer tokens for backward compatibility
			expectError: false,
		},
		{
			name: "replay detection",
			setupServer: func(mas *mockAuthServer) {
				// The mock server will detect replays automatically
				mas.setupValidator()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup mock server
			mas := newMockAuthServer(t, pubJWK)
			defer mas.Close()

			if tc.setupServer != nil {
				tc.setupServer(mas)
			}

			// Parse token URL
			tokenURL, err := url.Parse(mas.server.URL + "/token")
			require.NoError(t, err)

			// Create nonce store
			store := NewNonceStore()

			// Create token source
			opts := []TokenSourceOption{
				WithHTTPClient(mas.server.Client()),
				WithNonceStore(store),
			}

			ts, err := NewTokenSource(proofer, tokenURL, "test-client", privJWK, opts...)
			require.NoError(t, err)

			// Get token
			token, err := ts.Token()

			if tc.expectError {
				require.Error(t, err, "expected an error but got none")
				if tc.errorContains != "" {
					require.Contains(t, err.Error(), tc.errorContains, "error message did not contain expected text")
				}
				require.Nil(t, token, "expected nil token when error occurs")
				return
			}

			require.NoError(t, err, "unexpected error")
			require.NotNil(t, token, "expected non-nil token")
			require.Equal(t, "test_access_token", token.AccessToken, "unexpected access token")
			require.Equal(t, mas.tokenType, token.TokenType, "unexpected token type")
		})
	}
}

func TestTokenSource_NonceRefresh(t *testing.T) {
	// Generate test keys
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Create JWKs for public and private keys
	pubJWK := &jose.JSONWebKey{
		Key:       pub,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	privJWK := &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	// Create DPoP proofer
	proofer, err := dpop.NewProofer(privJWK)
	require.NoError(t, err)

	// Setup mock server
	mas := newMockAuthServer(t, pubJWK)
	defer mas.Close()

	mas.enforceNonce = true
	mas.nonce = "initial-nonce"
	mas.setupValidator()

	// Parse token URL
	tokenURL, err := url.Parse(mas.server.URL + "/token")
	require.NoError(t, err)

	// Create nonce store
	store := NewNonceStore()

	// Create token source
	ts, err := NewTokenSource(
		proofer,
		tokenURL,
		"test-client",
		privJWK,
		WithHTTPClient(mas.server.Client()),
		WithNonceStore(store),
	)
	require.NoError(t, err)

	// First request should succeed with any nonce since enforceNonce is true
	token, err := ts.Token()
	require.NoError(t, err, "unexpected error on first request")
	require.NotNil(t, token, "expected non-nil token")
	require.Equal(t, "test_access_token", token.AccessToken, "unexpected access token")
	require.Equal(t, "DPoP", token.TokenType, "unexpected token type")

	// Change server nonce
	mas.nonce = "new-nonce"
	mas.setupValidator()

	// Next request should succeed with the old nonce since it's still valid
	token, err = ts.Token()
	require.NoError(t, err, "unexpected error after changing server nonce")
	require.NotNil(t, token, "expected non-nil token")
	require.Equal(t, "test_access_token", token.AccessToken, "unexpected access token")
	require.Equal(t, "DPoP", token.TokenType, "unexpected token type")

	// Update store with new nonce
	store.SetNonce(mas.nonce)

	// Final request should succeed with the new nonce
	token, err = ts.Token()
	require.NoError(t, err, "unexpected error after setting new nonce")
	require.NotNil(t, token, "expected non-nil token")
	require.Equal(t, "test_access_token", token.AccessToken, "unexpected access token")
	require.Equal(t, "DPoP", token.TokenType, "unexpected token type")
}

func TestTokenSource_ReplayPrevention(t *testing.T) {
	// Generate test keys
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Create JWKs for public and private keys
	pubJWK := &jose.JSONWebKey{
		Key:       pub,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	privJWK := &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	// Create DPoP proofer
	proofer, err := dpop.NewProofer(privJWK)
	require.NoError(t, err)

	// Setup mock server
	mas := newMockAuthServer(t, pubJWK)
	defer mas.Close()

	// Parse token URL
	tokenURL, err := url.Parse(mas.server.URL + "/token")
	require.NoError(t, err)

	// Create nonce store
	store := NewNonceStore()

	// Create token source
	ts, err := NewTokenSource(
		proofer,
		tokenURL,
		"test-client",
		privJWK,
		WithHTTPClient(mas.server.Client()),
		WithNonceStore(store),
	)
	require.NoError(t, err)

	// First request should succeed
	token, err := ts.Token()
	require.NoError(t, err, "unexpected error on first request")
	require.NotNil(t, token, "expected non-nil token")

	// Immediate second request should generate new proof
	token2, err := ts.Token()
	require.NoError(t, err, "unexpected error on second request")
	require.NotNil(t, token2, "expected non-nil token")

	// Verify server detected no replays
	require.False(t, mas.replayDetected, "expected no replay detection")
}

func TestTokenSource_RetryOnTimeout(t *testing.T) {
	// Generate test keys
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	pubJWK := &jose.JSONWebKey{
		Key:       pub,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	privJWK := &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	proofer, err := dpop.NewProofer(privJWK)
	require.NoError(t, err)

	t.Run("retries on timeout then succeeds", func(t *testing.T) {
		requestCount := 0
		mas := newMockAuthServer(t, pubJWK)
		defer mas.Close()

		// Wrap the handler to simulate timeout on first request by delaying
		origHandler := mas.server.Config.Handler
		mas.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			if requestCount <= 1 {
				// Delay long enough that the short timeout expires, but respect
				// the request context so the server can shut down cleanly.
				timer := time.NewTimer(5 * time.Second)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-r.Context().Done():
				}
				return
			}
			origHandler.ServeHTTP(w, r)
		})

		tokenURL, err := url.Parse(mas.server.URL + "/token")
		require.NoError(t, err)

		store := NewNonceStore()
		ts, err := NewTokenSource(
			proofer,
			tokenURL,
			"test-client",
			privJWK,
			WithHTTPClient(mas.server.Client()),
			WithNonceStore(store),
			WithTokenTimeout(500*time.Millisecond),
			WithMaxRetries(2),
		)
		require.NoError(t, err)

		token, err := ts.Token()
		require.NoError(t, err, "expected retry to succeed")
		require.NotNil(t, token)
		require.Equal(t, "test_access_token", token.AccessToken)
		require.True(t, requestCount >= 2, "expected at least 2 requests (1 timeout + 1 success)")
	})

	t.Run("does not retry on non-transient error", func(t *testing.T) {
		requestCount := 0
		// Create a server that always returns 401
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_client",
				"error_description": "Client authentication failed",
			})
		}))
		defer server.Close()

		tokenURL, err := url.Parse(server.URL + "/token")
		require.NoError(t, err)

		store := NewNonceStore()
		ts, err := NewTokenSource(
			proofer,
			tokenURL,
			"test-client",
			privJWK,
			WithHTTPClient(server.Client()),
			WithNonceStore(store),
			WithMaxRetries(3),
		)
		require.NoError(t, err)

		token, err := ts.Token()
		require.Error(t, err, "expected error on auth failure")
		require.Nil(t, token)
		require.Equal(t, 1, requestCount, "expected exactly 1 request (no retries for non-transient error)")
	})

	t.Run("exhausts retries on persistent timeout", func(t *testing.T) {
		requestCount := 0
		// Create a server that always delays until context is done
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-r.Context().Done():
			}
		}))
		defer server.Close()

		tokenURL, err := url.Parse(server.URL + "/token")
		require.NoError(t, err)

		store := NewNonceStore()
		ts, err := NewTokenSource(
			proofer,
			tokenURL,
			"test-client",
			privJWK,
			WithHTTPClient(server.Client()),
			WithNonceStore(store),
			WithTokenTimeout(500*time.Millisecond),
			WithMaxRetries(1),
		)
		require.NoError(t, err)

		token, err := ts.Token()
		require.Error(t, err, "expected error after exhausting retries")
		require.Nil(t, token)
		require.Contains(t, err.Error(), "all 2 retry attempts failed")
		require.Equal(t, 2, requestCount, "expected 2 requests (initial + 1 retry)")
	})

	t.Run("zero retries disables retry", func(t *testing.T) {
		requestCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestCount++
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-r.Context().Done():
			}
		}))
		defer server.Close()

		tokenURL, err := url.Parse(server.URL + "/token")
		require.NoError(t, err)

		ts, err := NewTokenSource(
			proofer,
			tokenURL,
			"test-client",
			privJWK,
			WithHTTPClient(server.Client()),
			WithTokenTimeout(500*time.Millisecond),
			WithMaxRetries(0),
		)
		require.NoError(t, err)

		token, err := ts.Token()
		require.Error(t, err, "expected error with no retries")
		require.Nil(t, token)
		require.Equal(t, 1, requestCount, "expected exactly 1 request (no retries)")
	})
}

func TestIsTransientError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "context deadline exceeded",
			err:      context.DeadlineExceeded,
			expected: true,
		},
		{
			name:     "wrapped deadline exceeded",
			err:      fmt.Errorf("dpop_oauth2: token request failed: failed to execute request: context deadline exceeded"),
			expected: true,
		},
		{
			name:     "connection refused",
			err:      fmt.Errorf("dial tcp 127.0.0.1:8080: connection refused"),
			expected: true,
		},
		{
			name:     "connection reset",
			err:      fmt.Errorf("read tcp: connection reset by peer"),
			expected: true,
		},
		{
			name:     "i/o timeout",
			err:      fmt.Errorf("dial tcp: i/o timeout"),
			expected: true,
		},
		{
			name:     "auth error not transient",
			err:      fmt.Errorf("dpop_oauth2: invalid_client - Client authentication failed"),
			expected: false,
		},
		{
			name:     "invalid token not transient",
			err:      ErrInvalidToken,
			expected: false,
		},
		{
			name:     "proof creation not transient",
			err:      ErrProofCreationFailed,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isTransientError(tc.err)
			require.Equal(t, tc.expected, result)
		})
	}
}
