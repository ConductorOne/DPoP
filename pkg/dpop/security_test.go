package dpop

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurityScenarios(t *testing.T) {
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

	t.Run("replay attack prevention", func(t *testing.T) {
		store := NewMemoryJTIStore()
		validator := NewValidator(
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
			WithJTIStore(store.CheckAndStoreJTI),
			WithNonceValidator(func(ctx context.Context, nonce string) error {
				if nonce != "test-nonce-1" {
					return fmt.Errorf("invalid nonce")
				}
				return nil
			}),
		)

		// Create a valid proof
		proof, err := proofer.CreateProof(
			ctx,
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(5*time.Minute),
			WithStaticNonce("test-nonce-1"),
			WithAccessToken("access-token-123"),
		)
		require.NoError(t, err)

		// First use should succeed
		_, err = validator.ValidateProof(
			ctx,
			proof,
			"GET",
			"https://resource.example.org/protected",
			WithProofExpectedAccessToken("access-token-123"),
		)
		require.NoError(t, err)

		// Replay attempt should fail
		_, err = validator.ValidateProof(
			ctx,
			proof,
			"GET",
			"https://resource.example.org/protected",
			WithProofExpectedAccessToken("access-token-123"),
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate jti")
	})

	t.Run("token type confusion attack", func(t *testing.T) {
		validator := NewValidator(
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
		)

		// Create a JWT with wrong type
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"typ": "wrong+jwt",
				"jwk": jwk.Public(),
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

		// Validation should fail
		_, err = validator.ValidateProof(ctx, token, "GET", "https://resource.example.org/protected")
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

		// Validation should fail
		_, err = validator.ValidateProof(ctx, token, "GET", "https://resource.example.org/protected")
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
			ctx,
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
		_, err = validator.ValidateProof(ctx, modifiedToken, "GET", "https://resource.example.org/protected")
		assert.Error(t, err)

		// Test expired token
		claims.IssuedAt = jwt.NewNumericDate(pastTime)
		claims.NotBefore = jwt.NewNumericDate(pastTime)
		claims.Expiry = jwt.NewNumericDate(pastTime.Add(5 * time.Minute))

		modifiedToken, err = jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)

		// Validation should fail
		_, err = validator.ValidateProof(ctx, modifiedToken, "GET", "https://resource.example.org/protected")
		assert.Error(t, err)
	})

	t.Run("nonce downgrade attack", func(t *testing.T) {
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

		// Validation should fail
		_, err = validator.ValidateProof(ctx, proof, "GET", "https://resource.example.org/protected")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nonce required but not provided")
	})

	t.Run("HTTP method/URI manipulation", func(t *testing.T) {
		validator := NewValidator(
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
		)

		// Create proof for specific method/URI
		proof, err := proofer.CreateProof(
			ctx,
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(5*time.Minute),
		)
		require.NoError(t, err)

		// Try to use with different method
		_, err = validator.ValidateProof(ctx, proof, "POST", "https://resource.example.org/protected")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "method mismatch")

		// Try to use with different URI
		_, err = validator.ValidateProof(ctx, proof, "GET", "https://attacker.example.org/protected")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "URI mismatch")
	})

	t.Run("malformed JWT attacks", func(t *testing.T) {
		validator := NewValidator(
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
		)

		malformedTokens := []string{
			"",                               // Empty token
			"not.a.jwt",                      // Not base64
			"eyJ.eyJ.eyJ",                    // Invalid base64
			strings.Repeat("a", 1024*1024),   // Too large
			"header.",                        // Incomplete
			"header.payload",                 // Missing signature
			"header.payload.signature.extra", // Too many parts
		}

		for _, token := range malformedTokens {
			_, err := validator.ValidateProof(ctx, token, "GET", "https://resource.example.org/protected")
			assert.Error(t, err)
		}
	})
}
