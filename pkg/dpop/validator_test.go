package dpop

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
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
		WithNonceValidator(mockNonceValidator("test-nonce-123")),
		WithAccessTokenBindingValidator(mockAccessTokenBindingValidator("test-token-123", jwk)),
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
		require.True(t, jwkIsEqual(jwk, claims.PublicKey()))
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
			WithAccessTokenBindingValidator(mockAccessTokenBindingValidator("test-token-123", jwk)),
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

	t.Run("with access token binding validator", func(t *testing.T) {
		// Create a proofer with a key
		proofer, err := NewProofer(jwk)
		require.NoError(t, err)

		// Get the thumbprint of the key
		publicKey := proofer.key.Public()
		thumbprint, err := publicKey.Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		jkt := base64.RawURLEncoding.EncodeToString(thumbprint)

		// Create a mock access token with cnf/jkt claim
		mockAccessToken := fmt.Sprintf(`{"cnf":{"jkt":"%s"}}`, jkt)

		// Create a custom token binding validator
		tokenBindingValidator := func(ctx context.Context, accessToken string, pubKey *jose.JSONWebKey) error {
			// Verify the access token is what we expect
			assert.Equal(t, mockAccessToken, accessToken, "Access token should match expected value")

			// Verify the thumbprint matches
			actualThumbprint, err := pubKey.Thumbprint(crypto.SHA256)
			if err != nil {
				return fmt.Errorf("%w: failed to generate thumbprint: %v", ErrInvalidTokenBinding, err)
			}

			expectedThumbprint, err := base64.RawURLEncoding.DecodeString(jkt)
			if err != nil {
				return fmt.Errorf("%w: invalid jkt format: %v", ErrInvalidTokenBinding, err)
			}

			if subtle.ConstantTimeCompare(actualThumbprint, expectedThumbprint) != 1 {
				return fmt.Errorf("%w: thumbprint mismatch", ErrInvalidTokenBinding)
			}

			return nil
		}

		// Create a validator with the token binding validator
		validator := NewValidator(
			WithAccessTokenBindingValidator(tokenBindingValidator),
		)

		// Create a proof WITH the access token
		proof, err := proofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithAccessToken(mockAccessToken),
		)
		require.NoError(t, err)

		// Validate the proof
		claims, err := validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
			WithProofExpectedAccessToken(mockAccessToken),
		)
		require.NoError(t, err)
		require.NotNil(t, claims)
		require.NotNil(t, claims.PublicKey())

		// Verify the public key matches
		resultThumbprint, err := claims.PublicKey().Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		assert.Equal(t, thumbprint, resultThumbprint)

		// Test with invalid token
		_, err = validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
			WithProofExpectedAccessToken("invalid-token"),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid access token binding")

		// Test with mismatched thumbprint
		_, newPriv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		newJwk := &jose.JSONWebKey{
			Key:       newPriv,
			KeyID:     "test-key-2",
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}

		// Create a proofer with the new key
		newProofer, err := NewProofer(newJwk)
		require.NoError(t, err)

		// Create a proof with the new key
		newProof, err := newProofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithAccessToken(mockAccessToken),
		)
		require.NoError(t, err)

		// Validation should fail because the key doesn't match
		_, err = validator.ValidateProof(
			context.Background(),
			newProof,
			"GET",
			"https://resource.example.org/protected",
			WithProofExpectedAccessToken(mockAccessToken),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "thumbprint mismatch")
	})

	t.Run("no access token does not invoke validator", func(t *testing.T) {
		// Create a proofer with a key
		proofer, err := NewProofer(jwk)
		require.NoError(t, err)

		// Create a proof without an access token
		proof, err := proofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
		)
		require.NoError(t, err)

		// Create a validator with a token binding validator that would fail if called
		validatorCalled := false
		validator := NewValidator(
			WithAccessTokenBindingValidator(func(ctx context.Context, accessToken string, pubKey *jose.JSONWebKey) error {
				validatorCalled = true
				return fmt.Errorf("this validator should not be called")
			}),
		)

		// Validate the proof without an expected access token
		claims, err := validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
		)
		require.NoError(t, err)
		require.NotNil(t, claims)

		// Verify the validator was not called
		assert.False(t, validatorCalled, "Access token binding validator should not be called when no access token is expected")
	})

	t.Run("access token invokes validator correctly", func(t *testing.T) {
		// Create a proofer with a key
		proofer, err := NewProofer(jwk)
		require.NoError(t, err)

		// Get the thumbprint of the key
		publicKey := proofer.key.Public()
		thumbprint, err := publicKey.Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		jkt := base64.RawURLEncoding.EncodeToString(thumbprint)

		// Create a mock access token with cnf/jkt claim
		mockAccessToken := fmt.Sprintf(`{"cnf":{"jkt":"%s"}}`, jkt)

		// Create a validator with a token binding validator that tracks if it was called
		validatorCalled := false
		validator := NewValidator(
			WithAccessTokenBindingValidator(func(ctx context.Context, accessToken string, pubKey *jose.JSONWebKey) error {
				validatorCalled = true
				assert.Equal(t, mockAccessToken, accessToken, "Access token should match expected value")
				return nil
			}),
		)

		// Create a proof with the access token
		proof, err := proofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithAccessToken(mockAccessToken),
		)
		require.NoError(t, err)

		// Validate the proof with the expected access token
		claims, err := validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
			WithProofExpectedAccessToken(mockAccessToken),
		)
		require.NoError(t, err)
		require.NotNil(t, claims)

		// Verify the validator was called
		assert.True(t, validatorCalled, "Access token binding validator should be called when access token is expected")
	})

	t.Run("access token fails validator", func(t *testing.T) {
		// Create a proofer with a key
		proofer, err := NewProofer(jwk)
		require.NoError(t, err)

		// Create a mock access token
		mockAccessToken := "test-access-token"

		// Create a validator with a token binding validator that always fails
		validator := NewValidator(
			WithAccessTokenBindingValidator(func(ctx context.Context, accessToken string, pubKey *jose.JSONWebKey) error {
				return fmt.Errorf("%w: validator intentionally failed", ErrInvalidTokenBinding)
			}),
		)

		// Create a proof with the access token
		proof, err := proofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithAccessToken(mockAccessToken),
		)
		require.NoError(t, err)

		// Validation should fail because the validator fails
		_, err = validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
			WithProofExpectedAccessToken(mockAccessToken),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "validator intentionally failed")
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

	// Create validator that expects key1's public key
	validator := NewValidator(
		WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
		WithNonceValidator(func(ctx context.Context, nonce string) error {
			if nonce != "test-nonce-123" {
				return fmt.Errorf("invalid nonce")
			}
			return nil
		}),
		WithAccessTokenBindingValidator(func(ctx context.Context, accessToken string, publicKey *jose.JSONWebKey) error {
			// Verify the access token is what we expect
			assert.Equal(t, "test-token", accessToken, "Access token should match expected value")

			// Verify the public key matches the expected key
			assert.True(t, jwkIsEqual(jwk1, publicKey) || jwkIsEqual(jwk2, publicKey),
				"Public key should match one of the expected keys")

			return nil
		}),
	)

	pubKey := &jose.JSONWebKey{
		Key:       pub1,
		KeyID:     "test-key-1",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	t.Run("key_binding", func(t *testing.T) {
		// Create proof with key1
		proof1, err := proofer1.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(5*time.Minute),
			WithAccessToken("test-token"),
			WithStaticNonce("test-nonce-123"),
		)
		require.NoError(t, err)

		// Validate proof with key1
		claims, err := validator.ValidateProof(
			context.Background(),
			proof1,
			"GET",
			"https://resource.example.org/protected",
			WithProofExpectedAccessToken("test-token"),
			WithProofExpectedPublicKey(pubKey),
		)
		require.NoError(t, err)
		require.NotNil(t, claims)
		require.NotNil(t, claims.PublicKey())
	})
}

func TestJWTAccessTokenBindingValidator(t *testing.T) {
	// Generate a key pair for testing
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Get the thumbprint of the key
	publicKey := &jose.JSONWebKey{
		Key:       pub,
		KeyID:     "test-key-1",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}
	thumbprint, err := publicKey.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	jkt := base64.RawURLEncoding.EncodeToString(thumbprint)

	// Create the JWT access token binding validator
	validator := NewJWTAccessTokenBindingValidator([]jose.SignatureAlgorithm{jose.RS256})
	require.NotNil(t, validator)

	// Generate a key for signing the test JWTs
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Helper function to create a signed JWT with the given claims
	createJWT := func(claims map[string]interface{}) string {
		// Create a signer
		signingKey := jose.SigningKey{Algorithm: jose.RS256, Key: rsaPrivateKey}
		signer, err := jose.NewSigner(signingKey, nil)
		require.NoError(t, err)

		// Sign the claims
		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)

		return token
	}

	t.Run("valid JWT token with cnf/jkt claim", func(t *testing.T) {
		// Create a valid JWT token with cnf/jkt claim
		validToken := createJWT(map[string]interface{}{
			"cnf": map[string]interface{}{
				"jkt": jkt,
			},
		})

		// Validate the token binding
		err := validator(context.Background(), validToken, publicKey)
		require.NoError(t, err)
	})

	t.Run("malformed JWT token", func(t *testing.T) {
		// Create a malformed JWT token
		malformedToken := "not-a-jwt-token"

		// Validate the token binding
		err := validator(context.Background(), malformedToken, publicKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse access token")
	})

	t.Run("JWT token missing cnf claim", func(t *testing.T) {
		// Create a JWT token without cnf claim
		tokenWithoutCnf := createJWT(map[string]interface{}{
			"sub": "test",
		})

		// Validate the token binding
		err := validator(context.Background(), tokenWithoutCnf, publicKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no cnf claim in access token")
	})

	t.Run("JWT token with invalid cnf format", func(t *testing.T) {
		// Create a JWT token with invalid cnf format
		tokenWithInvalidCnf := createJWT(map[string]interface{}{
			"cnf": "not-a-map",
		})

		// Validate the token binding
		err := validator(context.Background(), tokenWithInvalidCnf, publicKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid cnf claim format")
	})

	t.Run("JWT token missing jkt claim", func(t *testing.T) {
		// Create a JWT token without jkt claim
		tokenWithoutJkt := createJWT(map[string]interface{}{
			"cnf": map[string]interface{}{
				"kid": "test-key-1",
			},
		})

		// Validate the token binding
		err := validator(context.Background(), tokenWithoutJkt, publicKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no jkt in cnf claim")
	})

	t.Run("JWT token with invalid jkt format", func(t *testing.T) {
		// Create a JWT token with invalid jkt format
		tokenWithInvalidJkt := createJWT(map[string]interface{}{
			"cnf": map[string]interface{}{
				"jkt": 123,
			},
		})

		// Validate the token binding
		err := validator(context.Background(), tokenWithInvalidJkt, publicKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid jkt format")
	})

	t.Run("JWT token with invalid jkt base64", func(t *testing.T) {
		// Create a JWT token with invalid base64 jkt
		tokenWithInvalidBase64 := createJWT(map[string]interface{}{
			"cnf": map[string]interface{}{
				"jkt": "not-base64!",
			},
		})

		// Validate the token binding
		err := validator(context.Background(), tokenWithInvalidBase64, publicKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid jkt format in token")
	})

	t.Run("JWT token with mismatched thumbprint", func(t *testing.T) {
		// Generate a different key
		otherPub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		otherPublicKey := &jose.JSONWebKey{
			Key:       otherPub,
			KeyID:     "test-key-2",
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}

		// Get the thumbprint of the other key
		otherThumbprint, err := otherPublicKey.Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		otherJkt := base64.RawURLEncoding.EncodeToString(otherThumbprint)

		// Create a JWT token with the other key's thumbprint
		tokenWithMismatchedThumbprint := createJWT(map[string]interface{}{
			"cnf": map[string]interface{}{
				"jkt": otherJkt,
			},
		})

		// Validate the token binding
		err = validator(context.Background(), tokenWithMismatchedThumbprint, publicKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "jkt mismatch")
	})
}
