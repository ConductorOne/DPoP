package dpop

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateProof(t *testing.T) {
	// Setup test keys and validator
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwk := &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key-1",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	proofer, err := NewProofer(jwk)
	require.NoError(t, err)

	validator := NewValidator(
		WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
		WithNonceValidator(func(ctx context.Context, nonce string) error {
			if nonce != "test-nonce-123" {
				return fmt.Errorf("invalid nonce")
			}
			return nil
		}),
	)

	cmpKeys := func(a, b *jose.JSONWebKey) bool {
		ah, err := a.Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		bh, err := b.Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		return bytes.Equal(ah, bh)
	}

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
			WithProofExpectedAccessToken("test-token-123"),
		)
		require.NoError(t, err)
		require.NotNil(t, claims)
		require.NotNil(t, claims.PublicKey())

		// Verify the claims
		require.Equal(t, "GET", claims.HTTPMethod)
		require.Equal(t, "https://resource.example.org/protected", claims.HTTPUri)
		require.NotEmpty(t, claims.Claims.ID)
		require.NotNil(t, claims.Claims.IssuedAt)
		// nbf and exp are optional, so we don't require them here

		// Verify the public key
		require.True(t, claims.PublicKey().IsPublic())
		require.True(t, claims.PublicKey().Valid())
		require.True(t, cmpKeys(jwk, claims.PublicKey()))
	})

	t.Run("valid proof without nbf and exp", func(t *testing.T) {
		// Create a JWT with only required claims
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"typ": DPoPHeaderTyp,
				"jwk": jwk.Public(),
			},
		})
		require.NoError(t, err)

		claims := &Claims{
			Claims: &jwt.Claims{
				ID:       uuid.New().String(),
				IssuedAt: jwt.NewNumericDate(time.Now()),
			},
			HTTPMethod: "GET",
			HTTPUri:    "https://resource.example.org/protected",
			Nonce:      "test-nonce-123",
			TokenHash:  hashAccessToken("test-token-123"),
		}

		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)

		// Validation should succeed
		validatedClaims, err := validator.ValidateProof(
			context.Background(),
			token,
			"GET",
			"https://resource.example.org/protected",
			WithProofExpectedAccessToken("test-token-123"),
		)
		require.NoError(t, err)
		require.NotNil(t, validatedClaims)
		require.Nil(t, validatedClaims.Claims.NotBefore)
		require.Nil(t, validatedClaims.Claims.Expiry)
	})

	t.Run("valid proof with only nbf", func(t *testing.T) {
		// Create a JWT with nbf but no exp
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"typ": DPoPHeaderTyp,
				"jwk": jwk.Public(),
			},
		})
		require.NoError(t, err)

		claims := &Claims{
			Claims: &jwt.Claims{
				ID:        uuid.New().String(),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now().Add(-30 * time.Second)),
			},
			HTTPMethod: "GET",
			HTTPUri:    "https://resource.example.org/protected",
			Nonce:      "test-nonce-123",
			TokenHash:  hashAccessToken("test-token-123"),
		}

		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)

		// Validation should succeed
		validatedClaims, err := validator.ValidateProof(
			context.Background(),
			token,
			"GET",
			"https://resource.example.org/protected",
			WithProofExpectedAccessToken("test-token-123"),
		)
		require.NoError(t, err)
		require.NotNil(t, validatedClaims)
		require.NotNil(t, validatedClaims.Claims.NotBefore)
		require.Nil(t, validatedClaims.Claims.Expiry)
	})

	t.Run("valid proof with only exp", func(t *testing.T) {
		// Create a JWT with exp but no nbf
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"typ": DPoPHeaderTyp,
				"jwk": jwk.Public(),
			},
		})
		require.NoError(t, err)

		claims := &Claims{
			Claims: &jwt.Claims{
				ID:       uuid.New().String(),
				IssuedAt: jwt.NewNumericDate(time.Now()),
				Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			},
			HTTPMethod: "GET",
			HTTPUri:    "https://resource.example.org/protected",
			Nonce:      "test-nonce-123",
			TokenHash:  hashAccessToken("test-token-123"),
		}

		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)

		// Validation should succeed
		validatedClaims, err := validator.ValidateProof(
			context.Background(),
			token,
			"GET",
			"https://resource.example.org/protected",
			WithProofExpectedAccessToken("test-token-123"),
		)
		require.NoError(t, err)
		require.NotNil(t, validatedClaims)
		require.Nil(t, validatedClaims.Claims.NotBefore)
		require.NotNil(t, validatedClaims.Claims.Expiry)
	})

	t.Run("invalid typ header", func(t *testing.T) {
		// Create a JWT with wrong typ
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"typ": "wrong+jwt",
				"jwk": jwk.Public(),
			},
		})
		require.NoError(t, err)

		claims := &Claims{
			Claims: &jwt.Claims{
				ID:        uuid.New().String(),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now().Add(-30 * time.Second)),
				Expiry:    jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			},
			HTTPMethod: "GET",
			HTTPUri:    "https://resource.example.org/protected",
			Nonce:      "test-nonce-123",
			TokenHash:  hashAccessToken("test-token-123"),
		}

		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)

		_, err = validator.ValidateProof(
			context.Background(),
			token,
			"GET",
			"https://resource.example.org/protected",
			WithProofExpectedAccessToken("test-token-123"),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token type")
	})

	t.Run("missing JWK attack", func(t *testing.T) {
		validator := NewValidator(
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
		)

		// Create a JWT without JWK
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"typ": DPoPHeaderTyp,
			},
		})
		require.NoError(t, err)

		claims := &Claims{
			Claims: &jwt.Claims{
				ID:        uuid.New().String(),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now().Add(-30 * time.Second)),
				Expiry:    jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			},
			HTTPMethod: "GET",
			HTTPUri:    "https://resource.example.org/protected",
			Nonce:      "test-nonce-123",
			TokenHash:  hashAccessToken("test-token-123"),
		}

		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)

		// Validation should fail
		_, err = validator.ValidateProof(
			context.Background(),
			token,
			"GET",
			"https://resource.example.org/protected",
			WithProofExpectedAccessToken("test-token-123"),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no embedded JWK")
	})

	t.Run("time manipulation attacks", func(t *testing.T) {
		validator := NewValidator(
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
			WithMaxClockSkew(30*time.Second),
		)

		futureTime := time.Now().Add(24 * time.Hour)
		pastTime := time.Now().Add(-24 * time.Hour)

		// Test future dated token
		proof, err := proofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(5*time.Minute),
		)
		require.NoError(t, err)

		// Modify the token to have future dates
		token, err := jwt.ParseSigned(proof, []jose.SignatureAlgorithm{jose.EdDSA})
		require.NoError(t, err)

		var claims Claims
		err = token.Claims(pub, &claims)
		require.NoError(t, err)

		claims.IssuedAt = jwt.NewNumericDate(futureTime)
		claims.NotBefore = jwt.NewNumericDate(futureTime)
		claims.Expiry = jwt.NewNumericDate(futureTime.Add(5 * time.Minute))

		// Create a new signer for the modified token
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"typ": DPoPHeaderTyp,
				"jwk": jwk.Public(),
			},
		})
		require.NoError(t, err)

		modifiedToken, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)

		// Validation should fail
		_, err = validator.ValidateProof(context.Background(), modifiedToken, "GET", "https://resource.example.org/protected", WithProofExpectedAccessToken("test-token-123"))
		assert.Error(t, err)

		// Test expired token
		claims.IssuedAt = jwt.NewNumericDate(pastTime)
		claims.NotBefore = jwt.NewNumericDate(pastTime)
		claims.Expiry = jwt.NewNumericDate(pastTime.Add(5 * time.Minute))

		modifiedToken, err = jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)

		// Validation should fail
		_, err = validator.ValidateProof(context.Background(), modifiedToken, "GET", "https://resource.example.org/protected", WithProofExpectedAccessToken("test-token-123"))
		assert.Error(t, err)
	})

	t.Run("nonce downgrade attack", func(t *testing.T) {
		validator := NewValidator(
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
			WithNonceValidator(mockNonceValidator("required-nonce")),
		)

		// Create proof without nonce
		proof, err := proofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(5*time.Minute),
			WithAccessToken("test-token-123"),
		)
		require.NoError(t, err)

		// Validation should fail
		_, err = validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
			WithProofExpectedAccessToken("test-token-123"),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nonce required but not provided")
	})

	t.Run("HTTP method/URI manipulation", func(t *testing.T) {
		validator := NewValidator(
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
		)

		// Create proof for specific method/URI
		proof, err := proofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(5*time.Minute),
		)
		require.NoError(t, err)

		// Try to use with different method
		_, err = validator.ValidateProof(context.Background(), proof, "POST", "https://resource.example.org/protected", WithProofExpectedAccessToken("test-token-123"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "method mismatch")

		// Try to use with different URI
		_, err = validator.ValidateProof(context.Background(), proof, "GET", "https://attacker.example.org/protected", WithProofExpectedAccessToken("test-token-123"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "URI mismatch")
	})

	t.Run("with confirmation claims", func(t *testing.T) {
		// Create a proofer with a key
		proofer, err := NewProofer(jwk)
		require.NoError(t, err)

		// Create a proof
		proof, err := proofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
		)
		require.NoError(t, err)

		// Get the thumbprint of the key
		publicKey := proofer.key.Public()
		thumbprint, err := publicKey.Thumbprint(crypto.SHA256)
		require.NoError(t, err)

		// Create a validator with confirmation claims
		validator := NewValidator()

		// Validate the proof
		claims, err := validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
			WithProofConfirmationClaims(map[string]string{
				"jkt": base64.RawURLEncoding.EncodeToString(thumbprint),
			}),
		)
		require.NoError(t, err)
		require.NotNil(t, claims)
		require.NotNil(t, claims.PublicKey())

		// Verify the public key matches
		resultThumbprint, err := claims.PublicKey().Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		assert.Equal(t, thumbprint, resultThumbprint)

		// Test with invalid thumbprint
		_, err = validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
			WithProofConfirmationClaims(map[string]string{
				"jkt": "invalid-thumbprint",
			}),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "jkt mismatch in confirmation claim")

		// Test with empty thumbprint
		_, err = validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
			WithProofConfirmationClaims(map[string]string{
				"jkt": "",
			}),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid jkt format in confirmation claims")

		// Test with mismatched thumbprint
		newKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		newJwk := &jose.JSONWebKey{
			Key:       newKey,
			KeyID:     "test-key-2",
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}
		newThumbprint, err := newJwk.Thumbprint(crypto.SHA256)
		require.NoError(t, err)

		_, err = validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
			WithProofConfirmationClaims(map[string]string{
				"jkt": base64.RawURLEncoding.EncodeToString(newThumbprint),
			}),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "jkt mismatch in confirmation claims")
	})
}

func TestKeyBinding(t *testing.T) {
	// Generate two different key pairs
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create JWKs for both keys
	jwk1 := &jose.JSONWebKey{
		Key:       priv1,
		KeyID:     "test-key-1",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	jwk2 := &jose.JSONWebKey{
		Key:       priv2,
		KeyID:     "test-key-2",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	// Create proofers with different keys
	proofer1, err := NewProofer(jwk1)
	require.NoError(t, err)

	proofer2, err := NewProofer(jwk2)
	require.NoError(t, err)

	// Create validator that expects key1's public key
	validator := NewValidator(
		WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
		WithNonceValidator(func(ctx context.Context, nonce string) error {
			if nonce != "test-nonce-123" {
				return fmt.Errorf("invalid nonce")
			}
			return nil
		}),
	)

	pubKey := &jose.JSONWebKey{
		Key:       pub1,
		KeyID:     "test-key-1",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	t.Run("key binding", func(t *testing.T) {
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
			WithProofExpectedAccessToken("test-token"),
			WithProofExpectedPublicKey(pubKey),
		)
		require.NoError(t, err)
		require.NotNil(t, claims)
		require.NotNil(t, claims.PublicKey())

		// Create proof with key2
		proof, err = proofer2.CreateProof(
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
			WithProofExpectedAccessToken("test-token"),
			WithProofExpectedPublicKey(pubKey),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid key binding")

		// Create proof without access token binding
		proof, err = proofer1.CreateProof(
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
			WithProofExpectedAccessToken("test-token"),
			WithProofExpectedPublicKey(pubKey),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing token hash")
	})
}
