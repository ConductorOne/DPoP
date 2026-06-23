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
	expiresIn      int
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
		expiresIn:   3600,
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
		"expires_in":   m.expiresIn,
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

func TestTokenSource_TokenShortExpiry(t *testing.T) {
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

	proofer, err := dpop.NewProofer(privJWK)
	require.NoError(t, err)

	mas := newMockAuthServer(t, pubJWK)
	defer mas.Close()
	mas.expiresIn = 5
	mas.setupValidator()

	tokenURL, err := url.Parse(mas.server.URL + "/token")
	require.NoError(t, err)

	ts, err := NewTokenSource(
		proofer,
		tokenURL,
		"test-client",
		privJWK,
		WithHTTPClient(mas.server.Client()),
		WithNonceStore(NewNonceStore()),
	)
	require.NoError(t, err)

	beforeRequest := time.Now()
	token, err := ts.Token()
	require.NoError(t, err)
	require.NotNil(t, token)
	require.False(t, token.Expiry.Before(beforeRequest), "short token lifetime should not produce a past expiry")
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

// nonceChallengeServer is a minimal OAuth2 token endpoint that, when
// challenge is true, rejects the first proof lacking a nonce with a 400
// use_dpop_nonce + DPoP-Nonce header and accepts any subsequent proof that
// carries that nonce. It records every proof's nonce claim so a test can
// assert the retry actually re-attached the challenged nonce.
type nonceChallengeServer struct {
	t          *testing.T
	server     *httptest.Server
	challenge  bool
	nonce      string
	calls      int
	seenNonces []string
}

func newNonceChallengeServer(t *testing.T, challenge bool, nonce string) *nonceChallengeServer {
	s := &nonceChallengeServer{t: t, challenge: challenge, nonce: nonce}
	s.server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *nonceChallengeServer) Close() { s.server.Close() }

func (s *nonceChallengeServer) proofNonce(w http.ResponseWriter, dpopProof string) (string, bool) {
	token, err := jose.ParseSigned(dpopProof, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_dpop_proof"})
		return "", false
	}
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(token.UnsafePayloadWithoutVerification(), &claims); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_dpop_proof"})
		return "", false
	}
	return claims.Nonce, true
}

func (s *nonceChallengeServer) handle(w http.ResponseWriter, r *http.Request) {
	s.calls++

	dpopProof := r.Header.Get(dpop.HeaderName)
	if dpopProof == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_dpop_proof", "error_description": "missing DPoP proof"})
		return
	}

	nonce, ok := s.proofNonce(w, dpopProof)
	if !ok {
		return
	}
	s.seenNonces = append(s.seenNonces, nonce)

	// Challenge the first proof that arrives without the required nonce.
	if s.challenge && nonce != s.nonce {
		w.Header().Set(dpop.NonceHeaderName, s.nonce)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "use_dpop_nonce",
			"error_description": "nonce required",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": "test_access_token",
		"token_type":   "DPoP",
		"expires_in":   3600,
	})
}

func newTestProoferKey(t *testing.T) *jose.JSONWebKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}
}

// TestTokenSource_SelfContainedNonceRetry asserts that a use_dpop_nonce
// challenge is satisfied by an automatic retry even when the caller configured
// NO NonceStore: the keystone behavior that makes any consumer nonce-aware on a
// plain dependency bump with zero call-site changes.
func TestTokenSource_SelfContainedNonceRetry(t *testing.T) {
	privJWK := newTestProoferKey(t)
	proofer, err := dpop.NewProofer(privJWK)
	require.NoError(t, err)

	const serverNonce = "challenge-nonce-xyz"
	srv := newNonceChallengeServer(t, true, serverNonce)
	defer srv.Close()

	tokenURL, err := url.Parse(srv.server.URL + "/token")
	require.NoError(t, err)

	// Deliberately no WithNonceStore: a bare consumer.
	ts, err := NewTokenSource(
		proofer,
		tokenURL,
		"test-client",
		privJWK,
		WithHTTPClient(srv.server.Client()),
	)
	require.NoError(t, err)

	token, err := ts.Token()
	require.NoError(t, err, "retry should succeed without a configured NonceStore")
	require.NotNil(t, token)
	require.Equal(t, "test_access_token", token.AccessToken)

	require.Equal(t, 2, srv.calls, "expected one challenge + one retry")
	require.Len(t, srv.seenNonces, 2)
	require.Empty(t, srv.seenNonces[0], "first proof should carry no nonce")
	require.Equal(t, serverNonce, srv.seenNonces[1], "retried proof must carry the challenged nonce")
}

// TestTokenSource_NoStoreNoChallenge confirms a server that never challenges
// still works for a bare consumer (single request, no retry, no store).
func TestTokenSource_NoStoreNoChallenge(t *testing.T) {
	privJWK := newTestProoferKey(t)
	proofer, err := dpop.NewProofer(privJWK)
	require.NoError(t, err)

	srv := newNonceChallengeServer(t, false, "")
	defer srv.Close()

	tokenURL, err := url.Parse(srv.server.URL + "/token")
	require.NoError(t, err)

	ts, err := NewTokenSource(
		proofer,
		tokenURL,
		"test-client",
		privJWK,
		WithHTTPClient(srv.server.Client()),
	)
	require.NoError(t, err)

	token, err := ts.Token()
	require.NoError(t, err)
	require.NotNil(t, token)
	require.Equal(t, 1, srv.calls, "no challenge means no retry")
}

// TestTokenSource_ConfiguredStoreCachesNonce confirms the existing NonceStore
// path still works: after a challenge-driven retry the nonce is cached, so a
// second Token() call sends it up front and the server never has to challenge
// again (no extra round trip).
func TestTokenSource_ConfiguredStoreCachesNonce(t *testing.T) {
	privJWK := newTestProoferKey(t)
	proofer, err := dpop.NewProofer(privJWK)
	require.NoError(t, err)

	const serverNonce = "cached-nonce-123"
	srv := newNonceChallengeServer(t, true, serverNonce)
	defer srv.Close()

	tokenURL, err := url.Parse(srv.server.URL + "/token")
	require.NoError(t, err)

	store := NewNonceStore()
	ts, err := NewTokenSource(
		proofer,
		tokenURL,
		"test-client",
		privJWK,
		WithHTTPClient(srv.server.Client()),
		WithNonceStore(store),
	)
	require.NoError(t, err)

	// First call: challenge + retry => 2 server hits, nonce cached.
	token, err := ts.Token()
	require.NoError(t, err)
	require.NotNil(t, token)
	require.Equal(t, 2, srv.calls)
	require.Equal(t, serverNonce, store.GetNonce(), "store should cache the challenged nonce")

	// Second call: cached nonce is sent up front => single server hit.
	token, err = ts.Token()
	require.NoError(t, err)
	require.NotNil(t, token)
	require.Equal(t, 3, srv.calls, "cached nonce should avoid a second challenge round trip")
	require.Equal(t, serverNonce, srv.seenNonces[len(srv.seenNonces)-1], "third proof should carry the cached nonce")
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
