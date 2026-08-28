package dpop_oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/conductorone/dpop/pkg/dpop"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

// fastRetry keeps retry tests quick while preserving the default attempt count.
func fastRetry() RetryConfig {
	return RetryConfig{
		MaxAttempts:  3,
		InitialDelay: time.Millisecond,
		MaxDelay:     4 * time.Millisecond,
	}
}

// scriptedTokenServer answers each token request with the next status in the
// script (the last entry repeats if calls continue past the end). A 200
// returns a valid token response; a 400 returns an invalid_client OAuth
// protocol error; anything else returns a bare error status. Every request's
// DPoP proof jti is recorded so tests can assert each attempt signed a fresh
// proof.
type scriptedTokenServer struct {
	t          *testing.T
	server     *httptest.Server
	mu         sync.Mutex
	script     []int
	calls      int
	proofJTIs  []string
	assertions []string
}

func newScriptedTokenServer(t *testing.T, script []int) *scriptedTokenServer {
	s := &scriptedTokenServer{t: t, script: script}
	s.server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.server.Close)
	return s
}

func (s *scriptedTokenServer) recordProof(r *http.Request) {
	proof := r.Header.Get(dpop.HeaderName)
	if proof == "" {
		s.proofJTIs = append(s.proofJTIs, "")
		return
	}
	token, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.EdDSA})
	require.NoError(s.t, err)
	var claims struct {
		JTI string `json:"jti"`
	}
	require.NoError(s.t, json.Unmarshal(token.UnsafePayloadWithoutVerification(), &claims))
	s.proofJTIs = append(s.proofJTIs, claims.JTI)
}

func (s *scriptedTokenServer) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.recordProof(r)
	require.NoError(s.t, r.ParseForm())
	s.assertions = append(s.assertions, r.PostFormValue("client_assertion"))

	idx := s.calls
	if idx >= len(s.script) {
		idx = len(s.script) - 1
	}
	s.calls++

	status := s.script[idx]
	w.Header().Set("Content-Type", "application/json")
	switch {
	case status == http.StatusOK:
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test_access_token",
			"token_type":   "DPoP",
			"expires_in":   3600,
		})
	case status == http.StatusBadRequest:
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_client",
			"error_description": "client authentication failed",
		})
	default:
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"error": "unavailable"})
	}
}

func (s *scriptedTokenServer) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *scriptedTokenServer) seenProofJTIs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.proofJTIs...)
}

func (s *scriptedTokenServer) seenAssertions() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.assertions...)
}

func newScriptedTokenSource(t *testing.T, srv *scriptedTokenServer, opts ...TokenSourceOption) *tokenSource {
	t.Helper()
	privJWK := newTestProoferKey(t)
	proofer, err := dpop.NewProofer(privJWK)
	require.NoError(t, err)

	tokenURL, err := url.Parse(srv.server.URL + "/token")
	require.NoError(t, err)

	opts = append([]TokenSourceOption{
		WithHTTPClient(srv.server.Client()),
		WithRetryConfig(fastRetry()),
	}, opts...)

	ts, err := NewTokenSource(proofer, tokenURL, "test-client", privJWK, opts...)
	require.NoError(t, err)
	return ts
}

// TestTokenSource_RetriesTransient5xx asserts that 5xx responses are retried
// until success and that every attempt carries a freshly signed DPoP proof
// and client assertion (distinct jtis) — an identical request is never
// replayed, even when retries land within the same second.
func TestTokenSource_RetriesTransient5xx(t *testing.T) {
	srv := newScriptedTokenServer(t, []int{http.StatusServiceUnavailable, http.StatusInternalServerError, http.StatusOK})
	ts := newScriptedTokenSource(t, srv)

	token, err := ts.Token()
	require.NoError(t, err, "transient 5xx responses should be retried to success")
	require.Equal(t, "test_access_token", token.AccessToken)
	require.Equal(t, 3, srv.callCount(), "expected two failed attempts plus one success")

	jtis := srv.seenProofJTIs()
	require.Len(t, jtis, 3)
	seenJTIs := make(map[string]bool, len(jtis))
	for _, jti := range jtis {
		require.NotEmpty(t, jti, "every attempt must carry a DPoP proof")
		require.False(t, seenJTIs[jti], "each attempt must sign a fresh proof (jti %q reused)", jti)
		seenJTIs[jti] = true
	}

	assertions := srv.seenAssertions()
	require.Len(t, assertions, 3)
	seenAssertions := make(map[string]bool, len(assertions))
	for _, assertion := range assertions {
		require.NotEmpty(t, assertion, "every attempt must carry a client assertion")
		require.False(t, seenAssertions[assertion], "each attempt must sign a fresh client assertion")
		seenAssertions[assertion] = true
	}
}

// TestTokenSource_RetryOn429 asserts throttling responses are retried.
func TestTokenSource_RetryOn429(t *testing.T) {
	srv := newScriptedTokenServer(t, []int{http.StatusTooManyRequests, http.StatusOK})
	ts := newScriptedTokenSource(t, srv)

	token, err := ts.Token()
	require.NoError(t, err)
	require.Equal(t, "test_access_token", token.AccessToken)
	require.Equal(t, 2, srv.callCount())
}

// TestTokenSource_RetriesExhausted asserts a persistent 5xx fails after
// MaxAttempts and that the returned error is classified transient while still
// matching ErrTokenRequestFailed.
func TestTokenSource_RetriesExhausted(t *testing.T) {
	srv := newScriptedTokenServer(t, []int{http.StatusServiceUnavailable})
	ts := newScriptedTokenSource(t, srv)

	token, err := ts.Token()
	require.Error(t, err)
	require.Nil(t, token)
	require.Equal(t, 3, srv.callCount(), "expected exactly MaxAttempts attempts")
	require.True(t, IsTransient(err), "persistent 5xx must classify as transient")
	require.ErrorIs(t, err, ErrTokenRequestTransient)
	require.ErrorIs(t, err, ErrTokenRequestFailed, "transient errors must still match ErrTokenRequestFailed")
	require.Contains(t, err.Error(), "503")
}

// TestTokenSource_NoRetryOnOAuthProtocolError asserts a definitive OAuth
// protocol rejection is returned immediately, without retries, and is not
// classified transient.
func TestTokenSource_NoRetryOnOAuthProtocolError(t *testing.T) {
	srv := newScriptedTokenServer(t, []int{http.StatusBadRequest})
	ts := newScriptedTokenSource(t, srv)

	token, err := ts.Token()
	require.Error(t, err)
	require.Nil(t, token)
	require.Equal(t, 1, srv.callCount(), "OAuth protocol errors must never be retried")
	require.False(t, IsTransient(err), "invalid_client is definitive, not transient")
	require.ErrorIs(t, err, ErrTokenRequestFailed)
	require.Contains(t, err.Error(), "invalid_client")
}

// TestTokenSource_RetriesDisabled asserts MaxAttempts=1 restores the old
// single-shot behavior.
func TestTokenSource_RetriesDisabled(t *testing.T) {
	srv := newScriptedTokenServer(t, []int{http.StatusServiceUnavailable})
	ts := newScriptedTokenSource(t, srv, WithRetryConfig(RetryConfig{MaxAttempts: 1}))

	_, err := ts.Token()
	require.Error(t, err)
	require.Equal(t, 1, srv.callCount())
	require.True(t, IsTransient(err), "classification applies even when retries are disabled")
}

// TestTokenSource_TransportErrorIsTransient asserts an error before any HTTP
// response (connection refused) is classified transient.
func TestTokenSource_TransportErrorIsTransient(t *testing.T) {
	srv := newScriptedTokenServer(t, []int{http.StatusOK})
	ts := newScriptedTokenSource(t, srv)
	srv.server.Close()

	token, err := ts.Token()
	require.Error(t, err)
	require.Nil(t, token)
	require.True(t, IsTransient(err), "transport errors must classify as transient")
	require.ErrorIs(t, err, ErrTokenRequestFailed)
}

// TestTokenSource_TimeoutIsTransient asserts a client-side timeout on the
// token POST is classified transient.
func TestTokenSource_TimeoutIsTransient(t *testing.T) {
	blocked := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-blocked:
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	// LIFO: unblock the handlers before slow.Close() waits on them.
	defer close(blocked)

	privJWK := newTestProoferKey(t)
	proofer, err := dpop.NewProofer(privJWK)
	require.NoError(t, err)

	tokenURL, err := url.Parse(slow.URL + "/token")
	require.NoError(t, err)

	ts, err := NewTokenSource(
		proofer,
		tokenURL,
		"test-client",
		privJWK,
		WithHTTPClient(&http.Client{Timeout: 50 * time.Millisecond}),
		WithRetryConfig(RetryConfig{MaxAttempts: 2, InitialDelay: time.Millisecond, MaxDelay: time.Millisecond}),
	)
	require.NoError(t, err)

	token, err := ts.Token()
	require.Error(t, err)
	require.Nil(t, token)
	require.True(t, IsTransient(err), "timeouts must classify as transient")
}

// TestTokenSource_NonceChallengeThenTransientRetry exercises the interplay of
// the two retry mechanisms: a use_dpop_nonce challenge is satisfied within an
// attempt, a subsequent 503 triggers the transient retry loop, and the retry
// succeeds using the nonce cached from the earlier challenge.
func TestTokenSource_NonceChallengeThenTransientRetry(t *testing.T) {
	const serverNonce = "interplay-nonce"

	var mu sync.Mutex
	calls := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++

		proof := r.Header.Get(dpop.HeaderName)
		token, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.EdDSA})
		require.NoError(t, err)
		var claims struct {
			Nonce string `json:"nonce"`
		}
		require.NoError(t, json.Unmarshal(token.UnsafePayloadWithoutVerification(), &claims))

		w.Header().Set("Content-Type", "application/json")
		switch {
		case claims.Nonce != serverNonce:
			w.Header().Set(dpop.NonceHeaderName, serverNonce)
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "use_dpop_nonce"})
		case calls == 2:
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "unavailable"})
		default:
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test_access_token",
				"token_type":   "DPoP",
				"expires_in":   3600,
			})
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(handler))
	defer srv.Close()

	privJWK := newTestProoferKey(t)
	proofer, err := dpop.NewProofer(privJWK)
	require.NoError(t, err)

	tokenURL, err := url.Parse(srv.URL + "/token")
	require.NoError(t, err)

	ts, err := NewTokenSource(
		proofer,
		tokenURL,
		"test-client",
		privJWK,
		WithHTTPClient(srv.Client()),
		WithNonceStore(NewNonceStore()),
		WithRetryConfig(fastRetry()),
	)
	require.NoError(t, err)

	token, err := ts.Token()
	require.NoError(t, err, "challenge + transient failure should still converge on success")
	require.Equal(t, "test_access_token", token.AccessToken)
	// Call 1: challenged. Call 2 (nonce retry): 503. Call 3 (transient retry,
	// cached nonce sent up front): success.
	require.Equal(t, 3, calls)
}

// TestTokenSource_NonceCarriedAcrossRetries asserts that a bare consumer (no
// NonceStore) does not get re-challenged on every transient retry: the nonce
// learned from the first use_dpop_nonce challenge is carried into subsequent
// outer attempts.
func TestTokenSource_NonceCarriedAcrossRetries(t *testing.T) {
	const serverNonce = "carried-nonce"

	var mu sync.Mutex
	calls := 0
	var seenNonces []string
	handler := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++

		proof := r.Header.Get(dpop.HeaderName)
		token, err := jose.ParseSigned(proof, []jose.SignatureAlgorithm{jose.EdDSA})
		require.NoError(t, err)
		var claims struct {
			Nonce string `json:"nonce"`
		}
		require.NoError(t, json.Unmarshal(token.UnsafePayloadWithoutVerification(), &claims))
		seenNonces = append(seenNonces, claims.Nonce)

		w.Header().Set("Content-Type", "application/json")
		switch {
		case claims.Nonce != serverNonce:
			w.Header().Set(dpop.NonceHeaderName, serverNonce)
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "use_dpop_nonce"})
		case calls == 2:
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "unavailable"})
		default:
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test_access_token",
				"token_type":   "DPoP",
				"expires_in":   3600,
			})
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(handler))
	defer srv.Close()

	privJWK := newTestProoferKey(t)
	proofer, err := dpop.NewProofer(privJWK)
	require.NoError(t, err)

	tokenURL, err := url.Parse(srv.URL + "/token")
	require.NoError(t, err)

	// Deliberately no NonceStore.
	ts, err := NewTokenSource(
		proofer,
		tokenURL,
		"test-client",
		privJWK,
		WithHTTPClient(srv.Client()),
		WithRetryConfig(fastRetry()),
	)
	require.NoError(t, err)

	token, err := ts.Token()
	require.NoError(t, err)
	require.Equal(t, "test_access_token", token.AccessToken)
	// Call 1: challenged. Call 2 (inner nonce retry): 503. Call 3 (outer
	// transient retry): carries the learned nonce up front, so the server
	// does not challenge again.
	require.Equal(t, 3, calls, "the outer retry must not trigger a second challenge round trip")
	require.Equal(t, []string{"", serverNonce, serverNonce}, seenNonces)
}

// TestTokenSource_CanceledContextIsNotTransient asserts that a caller
// abandoning the call (context cancellation) is not classified as a retryable
// transport failure.
func TestTokenSource_CanceledContextIsNotTransient(t *testing.T) {
	srv := newScriptedTokenServer(t, []int{http.StatusOK})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	privJWK := newTestProoferKey(t)
	proofer, err := dpop.NewProofer(privJWK)
	require.NoError(t, err)

	tokenURL, err := url.Parse(srv.server.URL + "/token")
	require.NoError(t, err)

	ts, err := NewTokenSource(
		proofer,
		tokenURL,
		"test-client",
		privJWK,
		WithBaseContext(ctx),
		WithHTTPClient(srv.server.Client()),
		WithRetryConfig(fastRetry()),
	)
	require.NoError(t, err)

	token, err := ts.Token()
	require.Error(t, err)
	require.Nil(t, token)
	require.False(t, IsTransient(err), "cancellation is not a transport failure and must not classify as transient")
	require.ErrorIs(t, err, ErrTokenRequestFailed)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 0, srv.callCount(), "no request should reach the server on a canceled context")
}

// TestIsTransient_Wrapping asserts classification survives additional
// wrapping by callers.
func TestIsTransient_Wrapping(t *testing.T) {
	base := markTransient(errors.New("boom"))
	wrapped := errors.Join(errors.New("outer"), base)
	require.True(t, IsTransient(wrapped))
	require.False(t, IsTransient(errors.New("boom")))
	require.False(t, IsTransient(nil))
}
