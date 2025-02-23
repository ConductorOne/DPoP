package dpop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateProof(t *testing.T) {
	// Setup test keys and validator
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	proofer, err := NewProofer(priv)
	require.NoError(t, err)

	validator := NewValidator(
		WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
	)

	// Helper function to create a valid proof
	createValidProof := func() string {
		proof, err := proofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(5*time.Minute),
			WithAccessToken("test-token-123"),
			WithStaticNonce("test-nonce-123"),
		)
		require.NoError(t, err)
		return proof
	}

	t.Run("valid proof", func(t *testing.T) {
		proof := createValidProof()
		claims, err := validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
		)
		require.NoError(t, err)
		assert.NotNil(t, claims)
	})

	t.Run("invalid typ header", func(t *testing.T) {
		// Create a JWT with wrong typ
		key := jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}
		signer, err := jose.NewSigner(key, &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"typ": "wrong+jwt",
				"jwk": map[string]interface{}{
					"kty": "OKP",
					"crv": "Ed25519",
					"x":   base64.RawURLEncoding.EncodeToString(pub),
				},
			},
		})
		require.NoError(t, err)

		claims := &Claims{
			Claims: &jwt.Claims{
				ID:        "test-id",
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now().Add(-30 * time.Second)),
				Expiry:    jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			},
			HTTPMethod: "GET",
			HTTPUri:    "https://resource.example.org/protected",
		}

		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)

		_, err = validator.ValidateProof(
			context.Background(),
			token,
			"GET",
			"https://resource.example.org/protected",
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token type")
	})

	t.Run("missing required claims", func(t *testing.T) {
		// Create proof without jti
		key := jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}
		signer, err := jose.NewSigner(key, &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"typ": "dpop+jwt",
				"jwk": map[string]interface{}{
					"kty": "OKP",
					"crv": "Ed25519",
					"x":   base64.RawURLEncoding.EncodeToString(pub),
				},
			},
		})
		require.NoError(t, err)

		claims := &Claims{
			Claims: &jwt.Claims{
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now().Add(-30 * time.Second)),
				Expiry:    jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			},
			HTTPMethod: "GET",
			HTTPUri:    "https://resource.example.org/protected",
		}

		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)

		_, err = validator.ValidateProof(
			context.Background(),
			token,
			"GET",
			"https://resource.example.org/protected",
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing required claim")
	})

	t.Run("method mismatch", func(t *testing.T) {
		proof := createValidProof()
		_, err := validator.ValidateProof(
			context.Background(),
			proof,
			"POST", // Different method
			"https://resource.example.org/protected",
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "method mismatch")
	})

	t.Run("URI mismatch", func(t *testing.T) {
		proof := createValidProof()
		_, err := validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://different.example.org/protected",
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "URI mismatch")
	})

	t.Run("expired proof", func(t *testing.T) {
		// Create proof with past expiry
		proof, err := proofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(-5*time.Minute), // Expired 5 minutes ago
			WithStaticNonce("test-nonce-123"),
		)
		require.NoError(t, err)

		_, err = validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("future proof", func(t *testing.T) {
		// Create proof with future nbf
		key := jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}
		signer, err := jose.NewSigner(key, &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"typ": "dpop+jwt",
				"jwk": map[string]interface{}{
					"kty": "OKP",
					"crv": "Ed25519",
					"x":   base64.RawURLEncoding.EncodeToString(pub),
				},
			},
		})
		require.NoError(t, err)

		claims := &Claims{
			Claims: &jwt.Claims{
				ID:        "test-id",
				IssuedAt:  jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				NotBefore: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
				Expiry:    jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
			},
			HTTPMethod: "GET",
			HTTPUri:    "https://resource.example.org/protected",
			Nonce:      "test-nonce-123",
		}

		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)

		_, err = validator.ValidateProof(
			context.Background(),
			token,
			"GET",
			"https://resource.example.org/protected",
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid iat")
	})

	t.Run("nonce validation", func(t *testing.T) {
		// Generate test key
		pub, priv, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)

		// Create signing key with private key
		signingKey := jose.JSONWebKey{
			Key:       priv,
			KeyID:     "test-key-1",
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}

		// Create verification key with public key
		verificationKey := jose.JSONWebKey{
			Key:       pub,
			KeyID:     "test-key-1",
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}

		timeBasedNonce, err := NewJWTNonce(signingKey, verificationKey)
		require.NoError(t, err)
		timeBasedNonce.Window = time.Second // Make nonces expire quickly
		validator := NewValidator(
			WithNonceValidator(timeBasedNonce.ValidateNonce),
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
		)

		// Create a proofer with the same key as the validator
		testProofer, err := NewProofer(priv)
		require.NoError(t, err)

		// Generate a valid nonce
		nonce, err := timeBasedNonce.GenerateNonce(context.Background())
		require.NoError(t, err)

		// Create proof with valid nonce
		proof, err := testProofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithStaticNonce(nonce),
			WithValidityDuration(10*time.Minute), // Increase validity duration
		)
		require.NoError(t, err)

		// Validate proof with valid nonce
		claims, err := validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
		)
		require.NoError(t, err)
		assert.Equal(t, nonce, claims.Nonce)

		// Create proof without nonce
		proof, err = testProofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(10*time.Minute), // Increase validity duration
		)
		require.NoError(t, err)

		// Validate proof without nonce (should fail)
		_, err = validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nonce required but not provided")

		// Create proof with expired nonce
		expiredNonce, err := timeBasedNonce.GenerateNonce(context.Background())
		require.NoError(t, err)
		// Wait for nonce to expire
		time.Sleep(3 * time.Second) // Wait longer than the 1-second window

		proof, err = testProofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithStaticNonce(expiredNonce),
			WithValidityDuration(10*time.Minute),
		)
		require.NoError(t, err)

		// Validation should fail
		_, err = validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nonce has expired")

		// Create proof with future nonce
		futureToken, err := timeBasedNonce.GenerateNonce(context.Background())
		require.NoError(t, err)

		// Create a new signer preserving the JWK
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"typ": "dpop-nonce+jwt",
				"kid": signingKey.KeyID,
			},
		})
		require.NoError(t, err)

		// Create claims with future timestamp
		futureNonceClaims := &nonceClaims{
			Claims: jwt.Claims{
				ID:        "test-id",
				IssuedAt:  jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
				NotBefore: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
				Expiry:    jwt.NewNumericDate(time.Now().Add(20 * time.Minute)),
			},
			Random: "test-random",
		}

		// Sign the claims
		var err2 error
		futureToken, err2 = jwt.Signed(signer).Claims(futureNonceClaims).Serialize()
		require.NoError(t, err2)

		proof, err = testProofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithStaticNonce(futureToken),
			WithValidityDuration(10*time.Minute),
		)
		require.NoError(t, err)

		// Validate proof with future nonce (should fail)
		_, err = validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nonce timestamp is in the future")
	})

	t.Run("access token binding", func(t *testing.T) {
		accessToken := "test-token-123"

		// Create proof with access token binding
		proof, err := proofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithAccessToken(accessToken),
			WithValidityDuration(10*time.Minute), // Increase validity duration
			WithStaticNonce("test-nonce-123"),
		)
		require.NoError(t, err)

		// Validate with correct token
		validator := NewValidator(
			WithExpectedAccessToken(accessToken),
			WithRequireAccessTokenBinding(true),
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
		)

		claims, err := validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
		)
		require.NoError(t, err)
		assert.NotEmpty(t, claims.TokenHash)

		// Validate with wrong token
		validator = NewValidator(
			WithExpectedAccessToken("wrong-token"),
			WithRequireAccessTokenBinding(true),
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
		)

		_, err = validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
		)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidTokenBinding, err)
	})

	t.Run("jti size limit", func(t *testing.T) {
		// Create proof with very large JTI
		largeJTI := strings.Repeat("x", 1024*1024) // 1MB JTI

		// Create a valid proof first
		proof, err := proofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(10*time.Minute),
		)
		require.NoError(t, err)

		// Parse the token to get the original headers
		token, err := jwt.ParseSigned(proof, []jose.SignatureAlgorithm{jose.EdDSA})
		require.NoError(t, err)

		// Create a new signer preserving the JWK
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, &jose.SignerOptions{
			EmbedJWK: true,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"typ": DPoPHeaderTyp,
				"jwk": token.Headers[0].JSONWebKey,
			},
		})
		require.NoError(t, err)

		// Create claims with large JTI
		claims := &Claims{
			Claims: &jwt.Claims{
				ID:        largeJTI,
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now().Add(-30 * time.Second)),
				Expiry:    jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
			},
			HTTPMethod: "GET",
			HTTPUri:    "https://resource.example.org/protected",
		}

		// Sign the modified claims
		modifiedProof, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)

		// Validate the proof
		_, err = validator.ValidateProof(
			context.Background(),
			modifiedProof,
			"GET",
			"https://resource.example.org/protected",
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "jti too large")
	})

	t.Run("nonce downgrade attack", func(t *testing.T) {
		// Create validator that requires nonces
		pub, priv, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)

		signingKey := jose.JSONWebKey{
			Key:       priv,
			KeyID:     "test-key-1",
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}

		verificationKey := jose.JSONWebKey{
			Key:       pub,
			KeyID:     "test-key-1",
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}

		timeBasedNonce, err := NewJWTNonce(signingKey, verificationKey)
		require.NoError(t, err)
		validator := NewValidator(
			WithNonceValidator(timeBasedNonce.ValidateNonce),
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
		)

		// Create a proofer with the same key as the validator
		testProofer, err := NewProofer(priv)
		require.NoError(t, err)

		// Generate a valid nonce
		nonce, err := timeBasedNonce.GenerateNonce(context.Background())
		require.NoError(t, err)

		// Create proof with nonce
		proofWithNonce, err := testProofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithStaticNonce(nonce),
			WithValidityDuration(10*time.Minute),
		)
		require.NoError(t, err)

		// Parse the token to get the original headers
		token, err := jwt.ParseSigned(proofWithNonce, []jose.SignatureAlgorithm{jose.EdDSA})
		require.NoError(t, err)

		// Create a new signer preserving the JWK
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, &jose.SignerOptions{
			EmbedJWK: true,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"typ": DPoPHeaderTyp,
				"jwk": token.Headers[0].JSONWebKey,
			},
		})
		require.NoError(t, err)

		// Create modified claims without nonce
		claims := &Claims{
			Claims: &jwt.Claims{
				ID:        "test-id",
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now().Add(-30 * time.Second)),
				Expiry:    jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
			},
			HTTPMethod: "GET",
			HTTPUri:    "https://resource.example.org/protected",
		}

		// Sign the modified claims
		modifiedProof, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)

		// Validate the modified proof (should fail)
		_, err = validator.ValidateProof(
			context.Background(),
			modifiedProof,
			"GET",
			"https://resource.example.org/protected",
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nonce required but not provided")
	})

}

func TestPreGenerationAttackPrevention(t *testing.T) {
	// Setup test keys and validator
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	proofer, err := NewProofer(priv)
	require.NoError(t, err)

	// Create a nonce validator that requires server-provided nonces
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	signingKey := jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key-1",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	verificationKey := jose.JSONWebKey{
		Key:       pub,
		KeyID:     "test-key-1",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	timeBasedNonce, err := NewJWTNonce(signingKey, verificationKey)
	require.NoError(t, err)
	timeBasedNonce.Window = time.Second // Short window for testing

	validator := NewValidator(
		WithNonceValidator(timeBasedNonce.ValidateNonce),
		WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
	)

	t.Run("pre-generated proof with future iat", func(t *testing.T) {
		// Generate a valid nonce
		nonce, err := timeBasedNonce.GenerateNonce(context.Background())
		require.NoError(t, err)

		futureTime := time.Now().Add(24 * time.Hour)

		// Create proof with future iat
		proof, err := proofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithStaticNonce(nonce),
			WithValidityDuration(10*time.Minute),
			WithProofNowFunc(func() time.Time { return futureTime }),
		)
		require.NoError(t, err)

		// Validation should fail
		_, err = validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid iat")
	})

	t.Run("pre-generated proof with expired nonce", func(t *testing.T) {
		// Generate a nonce
		nonce, err := timeBasedNonce.GenerateNonce(context.Background())
		require.NoError(t, err)

		// Wait for nonce to expire
		time.Sleep(2 * time.Second)

		// Create proof with expired nonce
		proof, err := proofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithStaticNonce(nonce),
			WithValidityDuration(10*time.Minute),
		)
		require.NoError(t, err)

		// Validation should fail
		_, err = validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nonce has expired")
	})
}

func TestKeyBinding(t *testing.T) {
	// Generate two different key pairs
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create proofers with different keys
	proofer1, err := NewProofer(priv1)
	require.NoError(t, err)

	proofer2, err := NewProofer(priv2)
	require.NoError(t, err)

	// Create validator that expects key1's public key
	validator := NewValidator(
		WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
		WithRequireAccessTokenBinding(true),
		WithExpectedAccessToken("test-token"),
		WithExpectedPublicKey(pub1),
	)

	t.Run("proof with correct key binding", func(t *testing.T) {
		// Create proof with key1
		proof, err := proofer1.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithAccessToken("test-token"),
			WithValidityDuration(10*time.Minute),
			WithStaticNonce("test-nonce-123"),
		)
		require.NoError(t, err)

		// Validation should succeed
		claims, err := validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
		)
		require.NoError(t, err)
		require.NotNil(t, claims)
	})

	t.Run("proof with wrong key binding", func(t *testing.T) {
		// Create proof with key2
		proof, err := proofer2.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithAccessToken("test-token"),
			WithValidityDuration(10*time.Minute),
			WithStaticNonce("test-nonce-123"),
		)
		require.NoError(t, err)

		// Validation should fail because it's signed with wrong key
		_, err = validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid key binding")
	})

	t.Run("proof with missing key binding", func(t *testing.T) {
		// Create proof without access token binding
		proof, err := proofer1.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(10*time.Minute),
			WithStaticNonce("test-nonce-123"),
		)
		require.NoError(t, err)

		// Validation should fail
		_, err = validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing token hash")
	})
}
