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
	"testing"

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

// newCredentialTestClient wires a DPoPCredentials backed by the given token
// source to a bufconn-hosted test service and returns a client for it.
func newCredentialTestClient(t *testing.T, tokenSource oauth2.TokenSource) pb.TestServiceClient {
	t.Helper()
	registerBufnetResolver()
	lis := bufconn.Listen(bufSize)

	s := grpc.NewServer()
	pb.RegisterTestServiceServer(s, &testServer{})
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
