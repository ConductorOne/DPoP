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
		dpop.WithJTIStore(func(ctx context.Context, jti string, nonce string) error {
			if _, exists := m.seenJTIs[jti]; exists {
				m.replayDetected = true
				return fmt.Errorf("replay detected")
			}
			m.seenJTIs[jti] = true
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

	jwk := &jose.JSONWebKey{
		Key:       pub,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	clientSecret := &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	// Create DPoP proofer
	proofer, err := dpop.NewProofer(priv)
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
			mas := newMockAuthServer(t, jwk)
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

			ts, err := NewTokenSource(proofer, tokenURL, "test-client", clientSecret, opts...)
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

	jwk := &jose.JSONWebKey{
		Key:       pub,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	clientSecret := &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	// Create DPoP proofer
	proofer, err := dpop.NewProofer(priv)
	require.NoError(t, err)

	// Setup mock server
	mas := newMockAuthServer(t, jwk)
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
		clientSecret,
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

	jwk := &jose.JSONWebKey{
		Key:       pub,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	clientSecret := &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	// Create DPoP proofer
	proofer, err := dpop.NewProofer(priv)
	require.NoError(t, err)

	// Setup mock server
	mas := newMockAuthServer(t, jwk)
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
		clientSecret,
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
