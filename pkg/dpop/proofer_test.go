package dpop

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewProofer tests the creation of a new proofer with valid and invalid keys
func TestNewProofer(t *testing.T) {
	t.Run("valid ed25519 key", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		proofer, err := NewProofer(priv)
		require.NoError(t, err)
		require.NotNil(t, proofer)

		// Verify the key was stored
		assert.Equal(t, priv, proofer.key)
		assert.NotEmpty(t, proofer.keyID)
	})

	t.Run("invalid key type", func(t *testing.T) {
		proofer, err := NewProofer("invalid key")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidKey, err)
		assert.Nil(t, proofer)
	})
}

// TestCreateProof tests the creation of DPoP proofs with various configurations
func TestCreateProof(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	proofer, err := NewProofer(priv)
	require.NoError(t, err)

	t.Run("basic proof creation", func(t *testing.T) {
		ctx := context.Background()
		method := "POST"
		url := "https://server.example.com/token"

		proof, err := proofer.CreateProof(ctx, method, url, nil)
		require.NoError(t, err)
		require.NotEmpty(t, proof)

		// Parse the proof to verify its contents
		parts := strings.Split(proof, ".")
		require.Len(t, parts, 3) // Header, payload, signature

		// Decode header
		headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
		require.NoError(t, err)

		var header struct {
			Type string                 `json:"typ"`
			Alg  string                 `json:"alg"`
			JWK  map[string]interface{} `json:"jwk"`
		}
		err = json.Unmarshal(headerJSON, &header)
		require.NoError(t, err)

		assert.Equal(t, "dpop+jwt", header.Type)
		assert.Equal(t, "EdDSA", header.Alg)
		assert.NotNil(t, header.JWK)

		// Decode payload
		payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, err)

		var payload struct {
			JTI string `json:"jti"`
			HTM string `json:"htm"`
			HTU string `json:"htu"`
			IAT int64  `json:"iat"`
		}
		err = json.Unmarshal(payloadJSON, &payload)
		require.NoError(t, err)

		assert.NotEmpty(t, payload.JTI)
		assert.Equal(t, method, payload.HTM)
		assert.Equal(t, url, payload.HTU)
		assert.InDelta(t, time.Now().Unix(), payload.IAT, 5)
	})

	t.Run("proof with custom options", func(t *testing.T) {
		ctx := context.Background()
		method := "GET"
		url := "https://resource.example.com/protected"

		proof, err := proofer.CreateProof(ctx, method, url,
			WithValidityDuration(10*time.Minute),
			WithStaticNonce("server-nonce-123"),
			WithAccessToken("access-token-123"),
		)
		require.NoError(t, err)
		require.NotEmpty(t, proof)

		// Parse and verify the token
		token, err := jwt.ParseSigned(proof, []jose.SignatureAlgorithm{jose.EdDSA})
		require.NoError(t, err)

		var claims Claims
		err = token.Claims(pub, &claims)
		require.NoError(t, err)

		// Verify all claims are present and correct
		assert.NotEmpty(t, claims.ID)
		assert.Equal(t, method, claims.HTTPMethod)
		assert.Equal(t, url, claims.HTTPUri)
		assert.Equal(t, "server-nonce-123", claims.Nonce)
		assert.NotEmpty(t, claims.TokenHash) // Access token hash should be present

		// Verify time-based claims
		now := time.Now()
		assert.True(t, claims.IssuedAt.Time().Before(now))
		assert.True(t, claims.NotBefore.Time().Before(now))
		assert.True(t, claims.Expiry.Time().After(now))
	})
}

// TestAccessTokenHash tests the access token hashing functionality
func TestAccessTokenHash(t *testing.T) {
	token := "test-access-token"
	hash := hashAccessToken(token)

	// Verify the hash is base64url encoded
	_, err := base64.RawURLEncoding.DecodeString(hash)
	require.NoError(t, err)

	// Verify deterministic hashing
	hash2 := hashAccessToken(token)
	assert.Equal(t, hash, hash2)

	// Verify different tokens produce different hashes
	differentHash := hashAccessToken("different-token")
	assert.NotEqual(t, hash, differentHash)
}
