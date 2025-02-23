package dpop

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTNonce(t *testing.T) {
	ctx := context.Background()

	// Generate test key
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Create signing key with private key
	signingKey := &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key-1",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	// Create verification key with public key
	verificationKey := &jose.JSONWebKey{
		Key:       pub,
		KeyID:     "test-key-1",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	nonce, err := NewJWTNonce(*signingKey, *verificationKey)
	require.NoError(t, err)

	t.Run("implements interfaces", func(t *testing.T) {
		var generator NonceGenerator = nonce.GenerateNonce
		var validator NonceValidator = nonce.ValidateNonce
		require.NotNil(t, generator)
		require.NotNil(t, validator)
	})

	t.Run("generate and validate", func(t *testing.T) {
		// Generate a nonce
		n1, err := nonce.GenerateNonce(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, n1)

		// Validate it
		err = nonce.ValidateNonce(ctx, n1)
		require.NoError(t, err)
	})

	t.Run("nonce uniqueness", func(t *testing.T) {
		// Generate multiple nonces and ensure they're unique
		nonces := make(map[string]bool)
		for i := 0; i < 100; i++ {
			n, err := nonce.GenerateNonce(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, n)
			assert.False(t, nonces[n], "Nonce should be unique")
			nonces[n] = true
		}
	})

	t.Run("nonce expiration", func(t *testing.T) {
		// Create nonce with short window
		shortNonce := &JWTNonce{
			Window: 1 * time.Second,
			Signer: nonce.Signer,
			Key:    nonce.Key,
		}

		// Generate and immediately validate
		n, err := shortNonce.GenerateNonce(ctx)
		require.NoError(t, err)
		err = shortNonce.ValidateNonce(ctx, n)
		require.NoError(t, err)

		// Wait for expiration
		time.Sleep(2 * time.Second)
		err = shortNonce.ValidateNonce(ctx, n)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("invalid nonce format", func(t *testing.T) {
		invalidNonces := []string{
			"",                   // Empty nonce
			"not-a-jwt",          // Not a JWT
			"header.body",        // Incomplete JWT
			"a.b.c.d",            // Too many parts
			"invalid.base64.sig", // Invalid base64
		}

		for _, n := range invalidNonces {
			err := nonce.ValidateNonce(ctx, n)
			assert.Error(t, err)
		}
	})

	t.Run("tampered nonce", func(t *testing.T) {
		// Generate valid nonce
		n, err := nonce.GenerateNonce(ctx)
		require.NoError(t, err)

		// Tamper with the nonce by changing the last character
		tamperedNonce := n[:len(n)-1] + "XYZ"
		err = nonce.ValidateNonce(ctx, tamperedNonce)
		assert.Error(t, err)
	})

	t.Run("wrong key validation", func(t *testing.T) {
		// Generate different key pair
		wrongPub, wrongPriv, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)

		// Create nonce generator with wrong key
		wrongSigningKey := jose.JSONWebKey{
			Key:       wrongPriv,
			KeyID:     "wrong-key",
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}

		wrongVerificationKey := jose.JSONWebKey{
			Key:       wrongPub,
			KeyID:     "wrong-key",
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}

		wrongNonce, err := NewJWTNonce(wrongSigningKey, wrongVerificationKey)
		require.NoError(t, err)

		// Generate nonce with wrong key
		n, err := wrongNonce.GenerateNonce(ctx)
		require.NoError(t, err)

		// Try to validate with original validator
		err = nonce.ValidateNonce(ctx, n)
		assert.Error(t, err)
	})

	t.Run("context cancellation", func(t *testing.T) {
		// Create cancelled context
		cancelledCtx, cancel := context.WithCancel(ctx)
		cancel()

		// Try to generate nonce with cancelled context
		_, err := nonce.GenerateNonce(cancelledCtx)
		assert.Error(t, err)

		// Try to validate nonce with cancelled context
		n, err := nonce.GenerateNonce(ctx)
		require.NoError(t, err)
		err = nonce.ValidateNonce(cancelledCtx, n)
		assert.Error(t, err)
	})
}
