package dpop_grpc

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	pb "github.com/conductorone/dpop/integrations/dpop_grpc/testdata"
	"github.com/conductorone/dpop/pkg/dpop"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

// testServer implements the test service
type testServer struct {
	pb.UnimplementedTestServiceServer
}

func (s *testServer) TestUnary(ctx context.Context, req *pb.TestRequest) (*pb.TestResponse, error) {
	claims, ok := dpop.ClaimsFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "DPoP claims not found in context")
	}

	return &pb.TestResponse{
		Message:   fmt.Sprintf("Received: %s", req.Message),
		DpopJti:   claims.Claims.ID,
		DpopHtm:   claims.HTTPMethod,
		DpopHtu:   claims.HTTPUri,
		DpopNonce: claims.Nonce,
	}, nil
}

func (s *testServer) TestStream(stream pb.TestService_TestStreamServer) error {
	claims, ok := dpop.ClaimsFromContext(stream.Context())
	if !ok {
		return status.Error(codes.Internal, "DPoP claims not found in context")
	}

	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}

		err = stream.Send(&pb.TestResponse{
			Message:   fmt.Sprintf("Received: %s", req.Message),
			DpopJti:   claims.Claims.ID,
			DpopHtm:   claims.HTTPMethod,
			DpopHtu:   claims.HTTPUri,
			DpopNonce: claims.Nonce,
		})
		if err != nil {
			return err
		}
	}
}

// mockTokenSource implements oauth2.TokenSource for testing
type mockTokenSource struct {
	token    *oauth2.Token
	tokenErr error
}

func (m *mockTokenSource) Token() (*oauth2.Token, error) {
	return m.token, m.tokenErr
}

// TestDPoPGRPC tests the DPoP gRPC interceptors
func TestDPoPGRPC(t *testing.T) {
	// Register bufnet resolver
	registerBufnetResolver()

	// Create a buffer for our in-memory gRPC server
	lis := bufconn.Listen(bufSize)

	// Generate test keys
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	require.NotNil(t, pub)

	// Create JWK for private key
	jwk := &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	// Create a static nonce generator for testing
	staticNonce := func(ctx context.Context) (string, error) {
		return "test-nonce", nil
	}

	// Create and start the gRPC server with DPoP interceptors
	s := grpc.NewServer(
		grpc.UnaryInterceptor(ServerUnaryInterceptor(
			WithNonceGenerator(staticNonce),
			WithAuthority("test-endpoint"),
			WithValidationOptions(
				dpop.WithNonceValidator(func(ctx context.Context, nonce string) error {
					t.Logf("Validating nonce: %s", nonce)
					if nonce != "test-nonce" {
						return dpop.ErrInvalidNonce
					}
					return nil
				}),
				dpop.WithMaxClockSkew(time.Minute),
				dpop.WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
			),
		)),
		grpc.StreamInterceptor(ServerStreamInterceptor(
			WithNonceGenerator(staticNonce),
			WithAuthority("test-endpoint"),
			WithValidationOptions(
				dpop.WithNonceValidator(func(ctx context.Context, nonce string) error {
					t.Logf("Validating nonce: %s", nonce)
					if nonce != "test-nonce" {
						return dpop.ErrInvalidNonce
					}
					return nil
				}),
				dpop.WithMaxClockSkew(time.Minute),
				dpop.WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
			),
		)),
	)
	pb.RegisterTestServiceServer(s, &testServer{})

	go func() {
		if err := s.Serve(lis); err != nil {
			t.Errorf("Server exited with error: %v", err)
		}
	}()
	defer s.Stop()

	// Create a client connection
	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	// Create the token source
	tokenSource := &mockTokenSource{
		token: &oauth2.Token{
			AccessToken: "test-access-token",
			TokenType:   "DPoP",
			Expiry:      time.Now().Add(time.Hour),
		},
	}
	proofer, err := dpop.NewProofer(jwk)
	require.NoError(t, err)

	// Create client credentials with DPoP
	creds, err := NewDPoPCredentials(proofer, tokenSource, "test-endpoint", []dpop.ProofOption{
		dpop.WithStaticNonce("test-nonce"),
		dpop.WithValidityDuration(time.Minute * 5),
		dpop.WithProofNowFunc(func() time.Time {
			return time.Now() // Use current time to avoid clock skew issues
		}),
	})
	require.NoError(t, err)
	// Disable TLS for testing
	creds.requireTLS = false

	// Create the client connection
	conn, err := grpc.NewClient(
		"bufnet://test-endpoint",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(creds),
	)
	require.NoError(t, err)
	defer conn.Close()

	client := pb.NewTestServiceClient(conn)

	t.Run("Unary call with valid DPoP proof", func(t *testing.T) {
		ctx := context.Background()
		// Add logging for the request
		md, _ := metadata.FromOutgoingContext(ctx)
		t.Logf("Outgoing metadata: %+v", md)

		resp, err := client.TestUnary(ctx, &pb.TestRequest{
			Message: "test message",
		})
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "test message")
		assert.NotEmpty(t, resp.DpopJti)
		assert.Equal(t, "POST", resp.DpopHtm)
		assert.Equal(t, "https://test-endpoint/test.TestService/TestUnary", resp.DpopHtu)
		assert.Equal(t, "test-nonce", resp.DpopNonce)
	})

	t.Run("Streaming call with valid DPoP proof", func(t *testing.T) {
		stream, err := client.TestStream(context.Background())
		require.NoError(t, err)

		// Send a message
		err = stream.Send(&pb.TestRequest{Message: "stream test"})
		require.NoError(t, err)

		// Receive the response
		resp, err := stream.Recv()
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "stream test")
		assert.NotEmpty(t, resp.DpopJti)
		assert.Equal(t, "POST", resp.DpopHtm)
		assert.Equal(t, "https://test-endpoint/test.TestService/TestStream", resp.DpopHtu)
		assert.Equal(t, "test-nonce", resp.DpopNonce)

		err = stream.CloseSend()
		require.NoError(t, err)
	})

	t.Run("Unary call with valid DPoP token in Authorization header", func(t *testing.T) {
		// Create a new client with a token source that returns a DPoP token
		tokenSource := &mockTokenSource{
			token: &oauth2.Token{
				AccessToken: "test-access-token-with-auth-header",
				TokenType:   "DPoP",
				Expiry:      time.Now().Add(time.Hour),
			},
		}

		// Create a new proofer with the same key
		proofer, err := dpop.NewProofer(jwk)
		require.NoError(t, err)

		// Create client credentials with DPoP and explicit token binding
		creds, err := NewDPoPCredentials(proofer, tokenSource, "test-endpoint", []dpop.ProofOption{
			dpop.WithStaticNonce("test-nonce"),
			dpop.WithValidityDuration(time.Minute * 5),
			dpop.WithProofNowFunc(func() time.Time {
				return time.Now() // Use current time to avoid clock skew issues
			}),
			// Add token binding to the proof
			dpop.WithAccessToken("test-access-token-with-auth-header"),
		})
		require.NoError(t, err)
		creds.requireTLS = false

		// Create a new connection with the credentials
		conn2, err := grpc.NewClient(
			"bufnet://test-endpoint",
			grpc.WithContextDialer(dialer),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithPerRPCCredentials(creds),
		)
		require.NoError(t, err)
		defer conn2.Close()

		client2 := pb.NewTestServiceClient(conn2)

		// Make the call
		resp, err := client2.TestUnary(context.Background(), &pb.TestRequest{
			Message: "test message with auth header",
		})
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "test message with auth header")
		assert.NotEmpty(t, resp.DpopJti)
		assert.Equal(t, "POST", resp.DpopHtm)
		assert.Equal(t, "https://test-endpoint/test.TestService/TestUnary", resp.DpopHtu)
		assert.Equal(t, "test-nonce", resp.DpopNonce)
	})
}

func TestDPoPGRPCErrors(t *testing.T) {
	lis := bufconn.Listen(bufSize)
	registerBufnetResolver()

	s := grpc.NewServer(
		grpc.UnaryInterceptor(ServerUnaryInterceptor()),
		grpc.StreamInterceptor(ServerStreamInterceptor()),
	)
	pb.RegisterTestServiceServer(s, &testServer{})

	go func() {
		if err := s.Serve(lis); err != nil {
			t.Errorf("Server exited with error: %v", err)
		}
	}()
	defer s.Stop()

	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	t.Run("Call without DPoP credentials", func(t *testing.T) {
		conn, err := grpc.NewClient(
			"bufnet://test-endpoint",
			grpc.WithContextDialer(dialer),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		require.NoError(t, err)
		defer conn.Close()

		client := pb.NewTestServiceClient(conn)
		_, err = client.TestUnary(context.Background(), &pb.TestRequest{
			Message: "test message",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		// We expect the middleware to allow the request to pass through
		// We'll then fail it in our real handler because we don't have DPoP claims
		assert.Equal(t, codes.Internal, st.Code())
		require.Equal(t, "DPoP claims not found in context", st.Message())
	})

	t.Run("Call with expired DPoP proof", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)
		require.NotNil(t, pub)

		jwk := &jose.JSONWebKey{
			Key:       priv,
			KeyID:     "test-key",
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}

		tokenSource := &mockTokenSource{
			token: &oauth2.Token{
				AccessToken: "test-access-token",
				TokenType:   "DPoP",
				Expiry:      time.Now().Add(time.Hour),
			},
		}

		proofer, err := dpop.NewProofer(jwk)
		require.NoError(t, err)

		// Create credentials with an old timestamp
		creds, err := NewDPoPCredentials(proofer, tokenSource, "test-endpoint", []dpop.ProofOption{
			dpop.WithProofNowFunc(func() time.Time {
				return time.Now().Add(-24 * time.Hour)
			}),
		})
		require.NoError(t, err)
		creds.requireTLS = false

		conn, err := grpc.NewClient(
			"bufnet://test-endpoint",
			grpc.WithContextDialer(dialer),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithPerRPCCredentials(creds),
		)
		require.NoError(t, err)
		defer conn.Close()

		client := pb.NewTestServiceClient(conn)
		_, err = client.TestUnary(context.Background(), &pb.TestRequest{
			Message: "test message",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
	})

	t.Run("Call with invalid Authorization scheme", func(t *testing.T) {
		// Create a client connection with Bearer token instead of DPoP
		conn, err := grpc.NewClient(
			"bufnet://test-endpoint",
			grpc.WithContextDialer(dialer),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		require.NoError(t, err)
		defer conn.Close()

		// Create context with Bearer token in metadata
		ctx := metadata.NewOutgoingContext(
			context.Background(),
			metadata.Pairs(
				dpop.HeaderName, "valid-dpop-proof", // Add a DPoP proof to trigger validation
				AuthorizationHeader, "Bearer invalid-token", // Use Bearer scheme instead of DPoP
			),
		)

		client := pb.NewTestServiceClient(conn)
		_, err = client.TestUnary(ctx, &pb.TestRequest{
			Message: "test message",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
		assert.Contains(t, st.Message(), "invalid authorization scheme")
	})

	t.Run("Call with DPoP Authorization but missing DPoP proof", func(t *testing.T) {
		// Create a client connection
		conn, err := grpc.NewClient(
			"bufnet://test-endpoint",
			grpc.WithContextDialer(dialer),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		require.NoError(t, err)
		defer conn.Close()

		// Create context with DPoP token in metadata but no proof
		ctx := metadata.NewOutgoingContext(
			context.Background(),
			metadata.Pairs(
				AuthorizationHeader, "DPoP valid-token", // Use DPoP scheme
				// Intentionally omit the DPoP proof header
			),
		)

		client := pb.NewTestServiceClient(conn)
		_, err = client.TestUnary(ctx, &pb.TestRequest{
			Message: "test message",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
		assert.Contains(t, st.Message(), "missing DPoP header")
	})

	t.Run("Call with malformed Authorization header", func(t *testing.T) {
		// Create a client connection
		conn, err := grpc.NewClient(
			"bufnet://test-endpoint",
			grpc.WithContextDialer(dialer),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		require.NoError(t, err)
		defer conn.Close()

		// Create context with malformed Authorization header
		ctx := metadata.NewOutgoingContext(
			context.Background(),
			metadata.Pairs(
				dpop.HeaderName, "valid-dpop-proof", // Add a DPoP proof to trigger validation
				AuthorizationHeader, "MalformedHeader", // Missing the token part
			),
		)

		client := pb.NewTestServiceClient(conn)
		_, err = client.TestUnary(ctx, &pb.TestRequest{
			Message: "test message",
		})
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
		assert.Contains(t, st.Message(), "invalid authorization scheme")
	})
}

func TestClientInterceptors(t *testing.T) {
	// Register bufnet resolver
	registerBufnetResolver()

	// Create a buffer for our in-memory gRPC server
	lis := bufconn.Listen(bufSize)

	// Generate test keys
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	require.NotNil(t, pub)

	// Create JWK for private key
	jwk := &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	// Create a static nonce generator for testing
	staticNonce := func(ctx context.Context) (string, error) {
		return "test-nonce", nil
	}

	// Create and start the gRPC server with DPoP interceptors
	s := grpc.NewServer(
		grpc.UnaryInterceptor(ServerUnaryInterceptor(
			WithNonceGenerator(staticNonce),
			WithAuthority("test-endpoint"),
			WithValidationOptions(
				dpop.WithNonceValidator(func(ctx context.Context, nonce string) error {
					t.Logf("Validating nonce: %s", nonce)
					if nonce != "test-nonce" {
						return dpop.ErrInvalidNonce
					}
					return nil
				}),
				dpop.WithMaxClockSkew(time.Minute),
				dpop.WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
			),
		)),
		grpc.StreamInterceptor(ServerStreamInterceptor(
			WithNonceGenerator(staticNonce),
			WithAuthority("test-endpoint"),
			WithValidationOptions(
				dpop.WithNonceValidator(func(ctx context.Context, nonce string) error {
					t.Logf("Validating nonce: %s", nonce)
					if nonce != "test-nonce" {
						return dpop.ErrInvalidNonce
					}
					return nil
				}),
				dpop.WithMaxClockSkew(time.Minute),
				dpop.WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
			),
		)),
	)
	pb.RegisterTestServiceServer(s, &testServer{})

	go func() {
		if err := s.Serve(lis); err != nil {
			t.Errorf("Server exited with error: %v", err)
		}
	}()
	defer s.Stop()

	// Create a client connection
	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	// Create the token source
	tokenSource := &mockTokenSource{
		token: &oauth2.Token{
			AccessToken: "test-access-token",
			TokenType:   "DPoP",
			Expiry:      time.Now().Add(time.Hour),
		},
	}

	// Create client interceptors
	unaryInterceptor, err := ClientUnaryInterceptor(jwk, tokenSource, []dpop.ProofOption{
		dpop.WithStaticNonce("test-nonce"),
		dpop.WithValidityDuration(time.Minute * 5),
		dpop.WithProofNowFunc(func() time.Time {
			return time.Now() // Use current time to avoid clock skew issues
		}),
	})
	require.NoError(t, err)

	streamInterceptor, err := ClientStreamInterceptor(jwk, tokenSource, []dpop.ProofOption{
		dpop.WithStaticNonce("test-nonce"),
		dpop.WithValidityDuration(time.Minute * 5),
		dpop.WithProofNowFunc(func() time.Time {
			return time.Now() // Use current time to avoid clock skew issues
		}),
	})
	require.NoError(t, err)

	// Create the client connection with interceptors
	conn, err := grpc.NewClient(
		"bufnet://test-endpoint",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(unaryInterceptor),
		grpc.WithStreamInterceptor(streamInterceptor),
	)
	require.NoError(t, err)
	defer conn.Close()

	client := pb.NewTestServiceClient(conn)

	t.Run("Unary call with interceptor", func(t *testing.T) {
		ctx := context.Background()
		// Add logging for the request
		md, _ := metadata.FromOutgoingContext(ctx)
		t.Logf("Outgoing metadata: %+v", md)

		resp, err := client.TestUnary(ctx, &pb.TestRequest{
			Message: "test message",
		})
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "test message")
		assert.NotEmpty(t, resp.DpopJti)
		assert.Equal(t, "POST", resp.DpopHtm)
		assert.Equal(t, "https://test-endpoint/test.TestService/TestUnary", resp.DpopHtu)
		assert.Equal(t, "test-nonce", resp.DpopNonce)
	})

	t.Run("Streaming call with interceptor", func(t *testing.T) {
		stream, err := client.TestStream(context.Background())
		require.NoError(t, err)

		// Send a message
		err = stream.Send(&pb.TestRequest{Message: "stream test"})
		require.NoError(t, err)

		// Receive the response
		resp, err := stream.Recv()
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "stream test")
		assert.NotEmpty(t, resp.DpopJti)
		assert.Equal(t, "POST", resp.DpopHtm)
		assert.Equal(t, "https://test-endpoint/test.TestService/TestStream", resp.DpopHtu)
		assert.Equal(t, "test-nonce", resp.DpopNonce)

		err = stream.CloseSend()
		require.NoError(t, err)
	})
}

func TestClientInterceptorErrors(t *testing.T) {
	// Register bufnet resolver
	registerBufnetResolver()

	// Create a buffer for our in-memory gRPC server
	lis := bufconn.Listen(bufSize)

	// Create and start the gRPC server with DPoP interceptors
	s := grpc.NewServer(
		grpc.UnaryInterceptor(ServerUnaryInterceptor()),
		grpc.StreamInterceptor(ServerStreamInterceptor()),
	)
	pb.RegisterTestServiceServer(s, &testServer{})

	go func() {
		if err := s.Serve(lis); err != nil {
			t.Errorf("Server exited with error: %v", err)
		}
	}()
	defer s.Stop()

	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	t.Run("Invalid private key", func(t *testing.T) {
		// Try to create interceptors with an invalid key
		invalidJWK := &jose.JSONWebKey{
			Key:       []byte("invalid-key"),
			KeyID:     "invalid-key",
			Algorithm: "invalid",
			Use:       "sig",
		}
		_, err := ClientUnaryInterceptor(invalidJWK, nil, nil)
		require.Error(t, err)

		_, err = ClientStreamInterceptor(invalidJWK, nil, nil)
		require.Error(t, err)
	})

	t.Run("Token source error", func(t *testing.T) {
		// Generate valid key
		pub, priv, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)
		require.NotNil(t, pub)

		jwk := &jose.JSONWebKey{
			Key:       priv,
			KeyID:     "test-key",
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}

		// Create a failing token source
		errorTokenSource := &mockTokenSource{
			token:    nil,
			tokenErr: errors.New("token source error"),
		}

		// Create interceptors
		unaryInterceptor, err := ClientUnaryInterceptor(jwk, errorTokenSource, nil)
		require.NoError(t, err)

		streamInterceptor, err := ClientStreamInterceptor(jwk, errorTokenSource, nil)
		require.NoError(t, err)

		// Create client with failing interceptors
		conn, err := grpc.NewClient(
			"bufnet://test-endpoint",
			grpc.WithContextDialer(dialer),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithUnaryInterceptor(unaryInterceptor),
			grpc.WithStreamInterceptor(streamInterceptor),
		)
		require.NoError(t, err)
		defer conn.Close()

		client := pb.NewTestServiceClient(conn)

		// Test unary call
		_, err = client.TestUnary(context.Background(), &pb.TestRequest{
			Message: "test message",
		})
		require.Error(t, err)

		// Test stream call
		_, err = client.TestStream(context.Background())
		require.Error(t, err)
	})

	t.Run("Invalid target URL", func(t *testing.T) {
		// Generate valid key
		pub, priv, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)
		require.NotNil(t, pub)

		jwk := &jose.JSONWebKey{
			Key:       priv,
			KeyID:     "test-key",
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}

		tokenSource := &mockTokenSource{
			token: &oauth2.Token{
				AccessToken: "test-access-token",
				TokenType:   "DPoP",
				Expiry:      time.Now().Add(time.Hour),
			},
		}

		// Create interceptors
		unaryInterceptor, err := ClientUnaryInterceptor(jwk, tokenSource, nil)
		require.NoError(t, err)

		streamInterceptor, err := ClientStreamInterceptor(jwk, tokenSource, nil)
		require.NoError(t, err)

		// Create client with invalid target
		conn, err := grpc.NewClient(
			"invalid://target",
			grpc.WithContextDialer(dialer),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithUnaryInterceptor(unaryInterceptor),
			grpc.WithStreamInterceptor(streamInterceptor),
		)
		require.NoError(t, err)
		defer conn.Close()

		client := pb.NewTestServiceClient(conn)

		// Test unary call
		_, err = client.TestUnary(context.Background(), &pb.TestRequest{
			Message: "test message",
		})
		require.Error(t, err)

		// Test stream call
		_, err = client.TestStream(context.Background())
		require.Error(t, err)
	})
}
