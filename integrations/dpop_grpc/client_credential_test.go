package dpop_grpc

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/conductorone/dpop/integrations/dpop_grpc/testdata"
	"github.com/conductorone/dpop/integrations/dpop_oauth2"
	"github.com/conductorone/dpop/pkg/dpop"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type credentialTestServer struct {
	pb.UnimplementedTestServiceServer
}

func (s *credentialTestServer) TestUnary(ctx context.Context, req *pb.TestRequest) (*pb.TestResponse, error) {
	return &pb.TestResponse{Message: req.Message}, nil
}

// newCredentialTestClient wires a DPoPCredentials backed by the given token
// source to a bufconn-hosted test service and returns a client for it.
func newCredentialTestClient(t *testing.T, tokenSource oauth2.TokenSource) pb.TestServiceClient {
	t.Helper()
	registerBufnetResolver()
	lis := bufconn.Listen(bufSize)

	s := grpc.NewServer()
	pb.RegisterTestServiceServer(s, &credentialTestServer{})
	go func() {
		_ = s.Serve(lis)
	}()
	t.Cleanup(s.Stop)

	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	jwk := &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}
	proofer, err := dpop.NewProofer(jwk)
	require.NoError(t, err)

	creds, err := NewDPoPCredentials(proofer, tokenSource, "test-endpoint", nil)
	require.NoError(t, err)
	creds.requireTLS = false

	conn, err := grpc.NewClient(
		"bufnet://test-endpoint",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(creds),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return pb.NewTestServiceClient(conn)
}

// TestDPoPCredentials_TokenErrorClassification asserts that token source
// failures surface as gRPC status codes that preserve the transient vs
// definitive distinction: transient failures map to Unavailable (retryable by
// callers' retry policies) and definitive failures map to Unauthenticated
// (fail fast).
func TestDPoPCredentials_TokenErrorClassification(t *testing.T) {
	tests := []struct {
		name     string
		tokenErr error
		wantCode codes.Code
	}{
		{
			name:     "transient token failure maps to Unavailable",
			tokenErr: fmt.Errorf("%w: unexpected status code: 503 Service Unavailable", dpop_oauth2.ErrTokenRequestTransient),
			wantCode: codes.Unavailable,
		},
		{
			name:     "definitive OAuth rejection maps to Unauthenticated",
			tokenErr: fmt.Errorf("%w: invalid_client - client authentication failed", dpop_oauth2.ErrTokenRequestFailed),
			wantCode: codes.Unauthenticated,
		},
		{
			name:     "unclassified error maps to Unauthenticated",
			tokenErr: errors.New("boom"),
			wantCode: codes.Unauthenticated,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := newCredentialTestClient(t, &mockTokenSource{tokenErr: tc.tokenErr})

			_, err := client.TestUnary(context.Background(), &pb.TestRequest{Message: "test"})
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok)
			require.Equal(t, tc.wantCode, st.Code())
			require.Contains(t, st.Message(), tc.tokenErr.Error())
		})
	}
}

// TestDPoPCredentials_EndToEndTransient503 exercises the full path: a real
// dpop_oauth2 token source hitting a token endpoint that persistently returns
// 503 must surface as codes.Unavailable on the gRPC call.
func TestDPoPCredentials_EndToEndTransient503(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"unavailable"}`, http.StatusServiceUnavailable)
	}))
	defer tokenSrv.Close()

	privJWK := &jose.JSONWebKey{
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	privJWK.Key = priv

	proofer, err := dpop.NewProofer(privJWK)
	require.NoError(t, err)

	tokenURL, err := url.Parse(tokenSrv.URL + "/token")
	require.NoError(t, err)

	ts, err := dpop_oauth2.NewTokenSource(
		proofer,
		tokenURL,
		"test-client",
		privJWK,
		dpop_oauth2.WithHTTPClient(tokenSrv.Client()),
		dpop_oauth2.WithRetryConfig(dpop_oauth2.RetryConfig{MaxAttempts: 1}),
	)
	require.NoError(t, err)

	client := newCredentialTestClient(t, ts)

	_, err = client.TestUnary(context.Background(), &pb.TestRequest{Message: "test"})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.Unavailable, st.Code(), "a 503 from the token endpoint must surface as Unavailable")
	require.Contains(t, st.Message(), "503")
}

func TestDPoPCredentials_TokenBudgetRetry(t *testing.T) {
	for _, cancelParent := range []bool{false, true} {
		name := "own_budget"
		if cancelParent {
			name = "caller_cancel"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls atomic.Int32
			release := make(chan struct{})
			tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					if cancelParent {
						cancel()
					}
					select {
					case <-r.Context().Done():
					case <-release:
					}
					return
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"access_token":"test_access_token","token_type":"DPoP","expires_in":3600}`)
			}))
			defer tokenSrv.Close()
			defer close(release)

			_, priv, err := ed25519.GenerateKey(nil)
			require.NoError(t, err)
			key := &jose.JSONWebKey{Key: priv, KeyID: "test-key", Algorithm: string(jose.EdDSA), Use: "sig"}
			proofer, err := dpop.NewProofer(key)
			require.NoError(t, err)
			tokenURL, err := url.Parse(tokenSrv.URL + "/token")
			require.NoError(t, err)
			ts, err := dpop_oauth2.NewTokenSource(proofer, tokenURL, "test-client", key,
				dpop_oauth2.WithBaseContext(ctx),
				dpop_oauth2.WithHTTPClient(tokenSrv.Client()),
				dpop_oauth2.WithRetryConfig(dpop_oauth2.RetryConfig{
					MaxAttempts:  3,
					InitialDelay: time.Millisecond,
					MaxDelay:     time.Millisecond,
					Timeout:      time.Minute,
				}),
			)
			require.NoError(t, err)
			client := newCredentialTestClient(t, ts)

			rpcCtx, rpcCancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer rpcCancel()
			_, err = client.TestUnary(rpcCtx, &pb.TestRequest{Message: "test"})
			require.Equal(t, int32(1), calls.Load(), "the expired call must stop its internal retries")
			if cancelParent {
				require.Equal(t, codes.Unauthenticated, status.Code(err), "caller cancellation must not trigger an outer retry")
				return
			}

			require.Equal(t, codes.Unavailable, status.Code(err), "an owned-budget timeout must allow an outer retry")
			response, err := client.TestUnary(rpcCtx, &pb.TestRequest{Message: "retry"})
			require.NoError(t, err)
			require.Equal(t, "retry", response.Message)
			require.Equal(t, int32(2), calls.Load(), "the outer retry must acquire a token with a fresh budget")
		})
	}
}
