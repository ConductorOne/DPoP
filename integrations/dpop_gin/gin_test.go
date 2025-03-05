package dpop_gin

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/conductorone/dpop/pkg/dpop"
	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)
}

func jwkIsEqual(a, b *jose.JSONWebKey) bool {
	ah, err := a.Thumbprint(crypto.SHA256)
	if err != nil {
		panic(err)
	}
	bh, err := b.Thumbprint(crypto.SHA256)
	if err != nil {
		panic(err)
	}
	return bytes.Equal(ah, bh)
}

// createTestGinEngine creates a Gin engine with DPoP middleware for testing
func createTestGinEngine(t *testing.T, opts ...ServerOption) (*gin.Engine, *jose.JSONWebKey) {
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

	// Create a Gin engine with DPoP middleware
	r := gin.New()
	r.Use(Middleware(opts...))

	// Add a test endpoint that returns the DPoP claims
	r.GET("/test", func(c *gin.Context) {
		claims, ok := GetClaims(c)
		require.True(t, ok, "DPoP claims should be present in context")
		require.NotNil(t, claims, "DPoP claims should not be nil")

		c.JSON(http.StatusOK, claims)
	})

	return r, jwk
}

// createDPoPProof creates a DPoP proof for testing
func createDPoPProof(t *testing.T, jwk *jose.JSONWebKey, method, url, accessToken, nonce string) string {
	proofer, err := dpop.NewProofer(jwk)
	require.NoError(t, err)

	var opts []dpop.ProofOption
	if accessToken != "" {
		opts = append(opts, dpop.WithAccessToken(accessToken))
	}
	if nonce != "" {
		opts = append(opts, dpop.WithStaticNonce(nonce))
	}

	proof, err := proofer.CreateProof(context.Background(), method, url, opts...)
	require.NoError(t, err)
	return proof
}

func TestDPoPBasicValidation(t *testing.T) {
	// Create a Gin engine with DPoP middleware
	validatorOpts := []dpop.Option{
		dpop.WithNonceValidator(func(ctx context.Context, nonce string) error {
			require.Equal(t, "test-nonce", nonce)
			return nil
		}),
		dpop.WithAccessTokenBindingValidator(func(ctx context.Context, accessToken string, publicKey *jose.JSONWebKey) error {
			return nil
		}),
	}
	r, jwk := createTestGinEngine(t, WithValidationOptions(validatorOpts...))

	// Create a test server
	ts := httptest.NewServer(r)
	defer ts.Close()

	// Create a test request
	req, _ := http.NewRequest("GET", ts.URL+"/test", nil)

	// Add DPoP proof header
	proof := createDPoPProof(t, jwk, "GET", ts.URL+"/test", "", "test-nonce")
	req.Header.Set(dpop.HeaderName, proof)

	// Perform the request
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check the response
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse the response body
	var claims dpop.Claims
	err = json.NewDecoder(resp.Body).Decode(&claims)
	require.NoError(t, err)

	// Verify the claims
	assert.Equal(t, "GET", claims.HTTPMethod)
	assert.Equal(t, ts.URL+"/test", claims.HTTPUri)
	assert.Equal(t, "test-nonce", claims.Nonce)
}

func TestDPoPWithAccessToken(t *testing.T) {
	// Create a Gin engine with DPoP middleware
	validatorOpts := []dpop.Option{
		dpop.WithNonceValidator(func(ctx context.Context, nonce string) error {
			require.Equal(t, "test-nonce", nonce)
			return nil
		}),
		dpop.WithAccessTokenBindingValidator(func(ctx context.Context, accessToken string, publicKey *jose.JSONWebKey) error {
			require.Equal(t, "test-access-token", accessToken)
			return nil
		}),
	}
	r, jwk := createTestGinEngine(t, WithValidationOptions(validatorOpts...))

	// Create a test server
	ts := httptest.NewServer(r)
	defer ts.Close()

	// Create a test request
	req, _ := http.NewRequest("GET", ts.URL+"/test", nil)

	// Add DPoP proof header with access token
	proof := createDPoPProof(t, jwk, "GET", ts.URL+"/test", "test-access-token", "test-nonce")
	req.Header.Set(dpop.HeaderName, proof)
	req.Header.Set("Authorization", "DPoP test-access-token")

	// Perform the request
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check the response
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse the response body
	var claims dpop.Claims
	err = json.NewDecoder(resp.Body).Decode(&claims)
	require.NoError(t, err)

	// Verify the claims
	assert.Equal(t, "GET", claims.HTTPMethod)
	assert.Equal(t, ts.URL+"/test", claims.HTTPUri)
	assert.Equal(t, "test-nonce", claims.Nonce)
	assert.NotEmpty(t, claims.TokenHash)
}

func TestDPoPErrorCases(t *testing.T) {
	testCases := []struct {
		name           string
		setupRequest   func(*http.Request, *jose.JSONWebKey, string)
		expectedStatus int
		expectedError  string
	}{
		{
			name: "Missing DPoP Header with DPoP Authorization",
			setupRequest: func(req *http.Request, jwk *jose.JSONWebKey, url string) {
				req.Header.Set("Authorization", "DPoP test-access-token")
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "DPoP header required",
		},
		{
			name: "Invalid Authorization Scheme",
			setupRequest: func(req *http.Request, jwk *jose.JSONWebKey, url string) {
				proof := createDPoPProof(t, jwk, "GET", url, "test-access-token", "test-nonce")
				req.Header.Set(dpop.HeaderName, proof)
				req.Header.Set("Authorization", "Bearer test-access-token")
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "Invalid authorization scheme",
		},
		{
			name: "Invalid DPoP Proof",
			setupRequest: func(req *http.Request, jwk *jose.JSONWebKey, url string) {
				req.Header.Set(dpop.HeaderName, "invalid-proof")
				req.Header.Set("Authorization", "DPoP test-access-token")
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "DPoP validation failed",
		},
		{
			name: "Method Mismatch",
			setupRequest: func(req *http.Request, jwk *jose.JSONWebKey, url string) {
				proof := createDPoPProof(t, jwk, "POST", url, "test-access-token", "test-nonce")
				req.Header.Set(dpop.HeaderName, proof)
				req.Header.Set("Authorization", "DPoP test-access-token")
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "DPoP validation failed",
		},
		{
			name: "URL Mismatch",
			setupRequest: func(req *http.Request, jwk *jose.JSONWebKey, url string) {
				proof := createDPoPProof(t, jwk, "GET", url+"/wrong-path", "test-access-token", "test-nonce")
				req.Header.Set(dpop.HeaderName, proof)
				req.Header.Set("Authorization", "DPoP test-access-token")
			},
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "DPoP validation failed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a Gin engine with DPoP middleware
			r, jwk := createTestGinEngine(t)

			// Create a test server
			ts := httptest.NewServer(r)
			defer ts.Close()

			// Create a test request
			req, _ := http.NewRequest("GET", ts.URL+"/test", nil)

			// Setup the request based on the test case
			tc.setupRequest(req, jwk, ts.URL+"/test")

			// Perform the request
			client := &http.Client{}
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			// Check the response
			require.Equal(t, tc.expectedStatus, resp.StatusCode)

			// Check the error message
			var response map[string]string
			err = json.NewDecoder(resp.Body).Decode(&response)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedError, response["error"])
		})
	}
}

func TestDPoPNonceHandling(t *testing.T) {
	// Create a nonce generator that returns a predictable nonce
	nonceGenerator := func(ctx context.Context) (string, error) {
		return "server-generated-nonce", nil
	}

	// Create a Gin engine with DPoP middleware and nonce generator
	validatorOpts := []dpop.Option{
		dpop.WithNonceValidator(func(ctx context.Context, nonce string) error {
			if nonce != "server-generated-nonce" {
				return fmt.Errorf("invalid nonce: %s", nonce)
			}
			return nil
		}),
		dpop.WithAccessTokenBindingValidator(func(ctx context.Context, accessToken string, publicKey *jose.JSONWebKey) error {
			return nil
		}),
	}

	// Create a Gin engine with DPoP middleware
	r := gin.New()
	r.Use(Middleware(
		WithValidationOptions(validatorOpts...),
		WithNonceGenerator(nonceGenerator),
	))

	// Add a test endpoint that doesn't require DPoP
	r.GET("/public", func(c *gin.Context) {
		c.String(http.StatusOK, "public endpoint")
	})

	// Add a test endpoint that returns the DPoP claims
	r.GET("/protected", func(c *gin.Context) {
		claims, ok := GetClaims(c)
		if !ok {
			c.String(http.StatusInternalServerError, "No DPoP claims found")
			return
		}
		c.JSON(http.StatusOK, claims)
	})

	// Create a test server
	ts := httptest.NewServer(r)
	defer ts.Close()

	// First request - should get a nonce in the response
	req1, _ := http.NewRequest("GET", ts.URL+"/public", nil)
	client := &http.Client{}
	resp1, err := client.Do(req1)
	require.NoError(t, err)
	defer resp1.Body.Close()

	// Check that the nonce header is set in the response
	nonce := resp1.Header.Get(dpop.NonceHeaderName)
	require.Equal(t, "server-generated-nonce", nonce)

	// Generate a key for the proof
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	jwk := &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	// Second request - use the nonce from the first response
	req2, _ := http.NewRequest("GET", ts.URL+"/protected", nil)
	proof := createDPoPProof(t, jwk, "GET", ts.URL+"/protected", "", nonce)
	req2.Header.Set(dpop.HeaderName, proof)
	resp2, err := client.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()

	// Check the response
	require.Equal(t, http.StatusOK, resp2.StatusCode)

	// Parse the response body
	var claims dpop.Claims
	err = json.NewDecoder(resp2.Body).Decode(&claims)
	require.NoError(t, err)

	// Verify the claims
	assert.Equal(t, "GET", claims.HTTPMethod)
	assert.Equal(t, ts.URL+"/protected", claims.HTTPUri)
	assert.Equal(t, nonce, claims.Nonce)
}

func TestDPoPOptionalEndpoints(t *testing.T) {
	// Create a Gin engine with DPoP middleware
	r, _ := createTestGinEngine(t)

	// Add an endpoint that doesn't require DPoP
	r.GET("/public", func(c *gin.Context) {
		c.String(http.StatusOK, "public endpoint")
	})

	// Create a test server
	ts := httptest.NewServer(r)
	defer ts.Close()

	// Test the public endpoint without DPoP
	req, _ := http.NewRequest("GET", ts.URL+"/public", nil)
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check the response
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "public endpoint", string(body))
}

func TestDPoPCustomErrorHandler(t *testing.T) {
	// Create a custom error handler
	customErrorHandler := func(c *gin.Context, err error) {
		c.String(http.StatusForbidden, "Custom error: %v", err)
	}

	// Create a Gin engine with DPoP middleware and custom error handler
	r, _ := createTestGinEngine(t, WithErrorHandler(customErrorHandler))

	// Create a test server
	ts := httptest.NewServer(r)
	defer ts.Close()

	// Create a test request with invalid DPoP proof
	req, _ := http.NewRequest("GET", ts.URL+"/test", nil)
	req.Header.Set(dpop.HeaderName, "invalid-proof")
	req.Header.Set("Authorization", "DPoP test-access-token")

	// Perform the request
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check the response
	require.Equal(t, http.StatusForbidden, resp.StatusCode)

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(body), "Custom error"))
}
