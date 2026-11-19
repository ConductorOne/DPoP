package dpop_oauth2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"testing/synctest"
	"time"

	"github.com/conductorone/dpop/pkg/dpop"
	"github.com/stretchr/testify/require"
)

type budgetTestTransport func(*http.Request) (*http.Response, error)

func (f budgetTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestTokenSource_TokenBudgetIsTransient(t *testing.T) {
	for _, duringBackoff := range []bool{false, true} {
		name := "request"
		if duringBackoff {
			name = "backoff"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				calls := 0
				client := &http.Client{Transport: budgetTestTransport(func(req *http.Request) (*http.Response, error) {
					calls++
					if duringBackoff {
						response := httptest.NewRecorder()
						response.WriteHeader(http.StatusServiceUnavailable)
						return response.Result(), nil
					}
					<-req.Context().Done()
					return nil, req.Context().Err()
				})}

				key := newTestProoferKey(t)
				proofer, err := dpop.NewProofer(key)
				require.NoError(t, err)
				tokenURL, err := url.Parse("https://example.com/token")
				require.NoError(t, err)
				ts, err := NewTokenSource(proofer, tokenURL, "test-client", key,
					WithHTTPClient(client),
					WithRetryConfig(RetryConfig{
						MaxAttempts:  3,
						InitialDelay: 2 * time.Minute,
						MaxDelay:     2 * time.Minute,
						Timeout:      time.Minute,
					}),
				)
				require.NoError(t, err)

				start := time.Now()
				token, err := ts.Token()
				require.Nil(t, token)
				require.ErrorIs(t, err, context.DeadlineExceeded)
				require.ErrorIs(t, err, ErrTokenRequestFailed)
				require.True(t, IsTransient(err), "the source's own budget must remain retryable by an outer caller")
				require.Equal(t, 30*time.Second, time.Since(start))
				require.Equal(t, 1, calls, "an expired token budget must stop further attempts")
			})
		})
	}
}

func TestTokenSource_ParentDeadlineDuringBackoffIsNotTransient(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		client := &http.Client{Transport: budgetTestTransport(func(req *http.Request) (*http.Response, error) {
			calls++
			response := httptest.NewRecorder()
			response.WriteHeader(http.StatusServiceUnavailable)
			return response.Result(), nil
		})}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		key := newTestProoferKey(t)
		proofer, err := dpop.NewProofer(key)
		require.NoError(t, err)
		tokenURL, err := url.Parse("https://example.com/token")
		require.NoError(t, err)
		ts, err := NewTokenSource(proofer, tokenURL, "test-client", key,
			WithBaseContext(ctx),
			WithHTTPClient(client),
			WithRetryConfig(RetryConfig{MaxAttempts: 3, InitialDelay: time.Minute, MaxDelay: time.Minute}),
		)
		require.NoError(t, err)

		token, err := ts.Token()
		require.Nil(t, token)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.ErrorIs(t, err, ErrTokenRequestFailed)
		require.False(t, IsTransient(err))
		require.Equal(t, 1, calls)
	})
}
