package dpop

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenBinding(t *testing.T) {
	ctx := context.Background()

	// Setup test keys and validator
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	jwk := &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key-1",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	proofer, err := NewProofer(jwk)
	require.NoError(t, err)

	t.Run("basic token binding", func(t *testing.T) {
		validator := NewValidator(
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
			WithNonceValidator(mockNonceValidator("test-nonce-123")),
			WithAccessTokenBindingValidator(mockAccessTokenBindingValidator("test-token-123", jwk)),
		)

		// Create proof with correct token binding
		proof, err := proofer.CreateProof(
			ctx,
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(5*time.Minute),
			WithAccessToken("test-token-123"),
			WithStaticNonce("test-nonce-123"),
		)
		require.NoError(t, err)

		// Validation should succeed
		claims, err := validator.ValidateProof(
			ctx,
			proof,
			"GET",
			"https://resource.example.org/protected",
			WithProofExpectedAccessToken("test-token-123"),
		)
		require.NoError(t, err)
		assert.NotEmpty(t, claims.TokenHash)
	})

	t.Run("missing token binding when expected", func(t *testing.T) {
		validator := NewValidator(
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
			WithNonceValidator(mockNonceValidator("test-nonce-123")),
		)

		// Create proof without token binding
		proof, err := proofer.CreateProof(
			ctx,
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(5*time.Minute),
			WithStaticNonce("test-nonce-123"),
		)
		require.NoError(t, err)

		// Validation should fail
		_, err = validator.ValidateProof(
			ctx,
			proof,
			"GET",
			"https://resource.example.org/protected",
			WithProofExpectedAccessToken("test-token-123"),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing token hash")
	})

	t.Run("unexpected token binding", func(t *testing.T) {
		validator := NewValidator(
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
			WithNonceValidator(mockNonceValidator("test-nonce-123")),
		)

		// Create proof with token binding when not expected
		proof, err := proofer.CreateProof(
			ctx,
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(5*time.Minute),
			WithAccessToken("test-token-123"),
			WithStaticNonce("test-nonce-123"),
		)
		require.NoError(t, err)

		// Validation should fail
		_, err = validator.ValidateProof(ctx, proof, "GET", "https://resource.example.org/protected")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected token hash")
	})

	t.Run("incorrect token binding", func(t *testing.T) {
		validator := NewValidator(
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
			WithNonceValidator(mockNonceValidator("test-nonce-123")),
		)

		// Create proof with wrong token
		proof, err := proofer.CreateProof(
			ctx,
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(5*time.Minute),
			WithAccessToken("wrong-token"),
			WithStaticNonce("test-nonce-123"),
		)
		require.NoError(t, err)

		// Validation should fail
		_, err = validator.ValidateProof(
			ctx,
			proof,
			"GET",
			"https://resource.example.org/protected",
			WithProofExpectedAccessToken("correct-token"),
		)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidTokenBinding, err)
	})

	t.Run("token hash computation", func(t *testing.T) {
		// Test vector for token hash computation
		token := "test-token-123"
		hash := sha256.Sum256([]byte(token))
		expectedHash := base64.RawURLEncoding.EncodeToString(hash[:])

		// Create proof with token binding
		proof, err := proofer.CreateProof(
			ctx,
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(5*time.Minute),
			WithAccessToken(token),
		)
		require.NoError(t, err)

		// Parse the proof to verify the hash
		parsedToken, err := jwt.ParseSigned(proof, []jose.SignatureAlgorithm{jose.EdDSA})
		require.NoError(t, err)

		var claims Claims
		err = parsedToken.Claims(pub, &claims)
		require.NoError(t, err)

		assert.Equal(t, expectedHash, claims.TokenHash)
	})

	t.Run("token binding with nonce", func(t *testing.T) {
		validator := NewValidator(
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
			WithNonceValidator(mockNonceValidator("test-nonce-123")),
			WithAccessTokenBindingValidator(mockAccessTokenBindingValidator("test-token-123", jwk)),
		)

		// Create proof with both token binding and nonce
		proof, err := proofer.CreateProof(
			ctx,
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(5*time.Minute),
			WithAccessToken("test-token-123"),
			WithStaticNonce("test-nonce-123"),
		)
		require.NoError(t, err)

		// Validation should succeed
		claims, err := validator.ValidateProof(
			ctx,
			proof,
			"GET",
			"https://resource.example.org/protected",
			WithProofExpectedAccessToken("test-token-123"),
		)
		require.NoError(t, err)
		assert.NotEmpty(t, claims.TokenHash)
		assert.Equal(t, "test-nonce-123", claims.Nonce)
	})

	t.Run("token binding with multiple proofs", func(t *testing.T) {
		validator := NewValidator(
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
			WithNonceValidator(mockNonceValidator("test-nonce-123")),
			WithAccessTokenBindingValidator(mockAccessTokenBindingValidator("test-token-123", jwk)),
		)

		// Create multiple proofs with same token binding
		for i := 0; i < 5; i++ {
			proof, err := proofer.CreateProof(
				ctx,
				"GET",
				"https://resource.example.org/protected",
				WithValidityDuration(5*time.Minute),
				WithAccessToken("test-token-123"),
				WithStaticNonce("test-nonce-123"),
			)
			require.NoError(t, err)

			// Each validation should succeed
			claims, err := validator.ValidateProof(
				ctx,
				proof,
				"GET",
				"https://resource.example.org/protected",
				WithProofExpectedAccessToken("test-token-123"),
			)
			require.NoError(t, err)
			assert.NotEmpty(t, claims.TokenHash)
		}
	})

	t.Run("access token binding requirements", func(t *testing.T) {
		// Case 1: When expectedAccessToken is provided, ath claim must be present and match
		validator := NewValidator(
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
		)

		// Create proof without token binding
		proof, err := proofer.CreateProof(
			ctx,
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(5*time.Minute),
		)
		require.NoError(t, err)

		// Validation should fail due to missing token hash
		_, err = validator.ValidateProof(
			ctx,
			proof,
			"GET",
			"https://resource.example.org/protected",
			WithProofExpectedAccessToken("test-token-123"),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing token hash")

		// Case 2: When expectedAccessToken is not provided, ath claim must be empty
		validator = NewValidator(
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
		)

		// Create proof with token binding when not expected
		proof, err = proofer.CreateProof(
			ctx,
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(5*time.Minute),
			WithAccessToken("test-token-123"),
		)
		require.NoError(t, err)

		// Validation should fail due to unexpected token hash
		_, err = validator.ValidateProof(ctx, proof, "GET", "https://resource.example.org/protected")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected token hash")
	})

	t.Run("nonce requirements", func(t *testing.T) {
		// Case 1: When nonceValidator is provided, nonce claim must be present and valid
		validator := NewValidator(
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
			WithNonceValidator(mockNonceValidator("required-nonce")),
		)

		// Create proof without nonce
		proof, err := proofer.CreateProof(
			ctx,
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(5*time.Minute),
		)
		require.NoError(t, err)

		// Validation should fail due to missing nonce
		_, err = validator.ValidateProof(ctx, proof, "GET", "https://resource.example.org/protected")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nonce required but not provided")

		// Case 2: When nonceValidator is not provided, nonce claim must be empty
		validator = NewValidator(
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
		)

		// Create proof with nonce when not expected
		proof, err = proofer.CreateProof(
			ctx,
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(5*time.Minute),
			WithStaticNonce("test-nonce-123"),
		)
		require.NoError(t, err)

		// Validation should fail due to unexpected nonce
		_, err = validator.ValidateProof(ctx, proof, "GET", "https://resource.example.org/protected")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected nonce")
	})
}

// mockNonceValidator creates a simple nonce validator function for testing
func mockNonceValidator(expectedNonce string) NonceValidator {
	return func(_ context.Context, nonce string) error {
		if nonce != expectedNonce {
			return ErrInvalidNonce
		}
		return nil
	}
}

// mockAccessTokenBindingValidator creates a simple access token binding validator function for testing
func mockAccessTokenBindingValidator(expectedAccessToken string, jwk *jose.JSONWebKey) AccessTokenBindingValidator {
	return func(_ context.Context, accessToken string, publicKey *jose.JSONWebKey) error {
		if accessToken != expectedAccessToken {
			return fmt.Errorf("%w: expected access token %v, got %v", ErrInvalidTokenBinding, expectedAccessToken, accessToken)
		}
		if !jwkIsEqual(jwk, publicKey) {
			return fmt.Errorf("%w: expected public key %v, got %v", ErrInvalidTokenBinding, jwk, publicKey)
		}
		return nil
	}
}
