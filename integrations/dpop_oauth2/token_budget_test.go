package dpop_oauth2

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

type budgetTestBody struct {
	ctx context.Context
}

func (b *budgetTestBody) Read(p []byte) (int, error) {
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (b *budgetTestBody) Close() error { return nil }

func TestTokenSource_TokenBudgetIsTransient(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{name: "request"},
		{name: "backoff", status: http.StatusServiceUnavailable},
		{name: "token_body", status: http.StatusOK},
		{name: "error_body", status: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				calls := 0
				client := &http.Client{Transport: budgetTestTransport(func(req *http.Request) (*http.Response, error) {
					calls++
					if tc.status != 0 {
						response := httptest.NewRecorder()
						response.WriteHeader(tc.status)
						resp := response.Result()
						if tc.status == http.StatusOK || tc.status == http.StatusBadRequest {
							resp.Body = &budgetTestBody{ctx: req.Context()}
						}
						return resp, nil
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

func TestTokenSource_ResponseBodyTimeoutClassification(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusBadRequest} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			for _, mode := range []string{"attempt_retry", "attempt_exhaustion", "parent_deadline", "parent_cancel", "malformed"} {
				t.Run(mode, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						ctx := context.Background()
						cfg := RetryConfig{MaxAttempts: 2, InitialDelay: time.Millisecond, MaxDelay: time.Millisecond, Timeout: time.Minute}
						switch mode {
						case "attempt_retry", "attempt_exhaustion":
							cfg.Timeout = 5 * time.Second
							if mode == "attempt_exhaustion" {
								cfg.MaxAttempts = 1
							}
						case "parent_deadline":
							var cancel context.CancelFunc
							ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
							defer cancel()
						case "parent_cancel":
							var cancel context.CancelFunc
							ctx, cancel = context.WithCancel(ctx)
							defer cancel()
							time.AfterFunc(5*time.Second, cancel)
						}

						calls := 0
						client := &http.Client{Transport: budgetTestTransport(func(req *http.Request) (*http.Response, error) {
							calls++
							response := httptest.NewRecorder()
							if calls > 1 {
								response.WriteString(`{"access_token":"test_access_token","token_type":"DPoP","expires_in":3600}`)
								return response.Result(), nil
							}
							response.WriteHeader(status)
							resp := response.Result()
							if mode == "malformed" {
								resp.Body = io.NopCloser(strings.NewReader("{"))
							} else {
								resp.Body = &budgetTestBody{ctx: req.Context()}
							}
							return resp, nil
						})}

						key := newTestProoferKey(t)
						proofer, err := dpop.NewProofer(key)
						require.NoError(t, err)
						tokenURL, err := url.Parse("https://example.com/token")
						require.NoError(t, err)
						ts, err := NewTokenSource(proofer, tokenURL, "test-client", key,
							WithBaseContext(ctx), WithHTTPClient(client), WithRetryConfig(cfg),
						)
						require.NoError(t, err)

						token, err := ts.Token()
						if mode == "attempt_retry" {
							require.NoError(t, err)
							require.Equal(t, "test_access_token", token.AccessToken)
							require.Equal(t, 2, calls)
							return
						}
						require.Nil(t, token)
						require.Error(t, err)
						require.Equal(t, 1, calls)
						require.Equal(t, mode == "attempt_exhaustion", IsTransient(err))
						if mode == "attempt_exhaustion" {
							require.ErrorIs(t, err, context.DeadlineExceeded)
							require.ErrorIs(t, err, ErrTokenRequestFailed)
						} else if ctx.Err() != nil {
							require.ErrorIs(t, err, ctx.Err())
						}
						if status == http.StatusOK {
							require.ErrorIs(t, err, ErrInvalidToken)
						} else {
							require.ErrorIs(t, err, ErrTokenRequestFailed)
						}
					})
				})
			}
		})
	}
}
