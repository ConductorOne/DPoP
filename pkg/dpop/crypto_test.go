package dpop

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCryptoOperations(t *testing.T) {
	t.Run("key algorithm compatibility", func(t *testing.T) {
		// Test Ed25519 key with proofer
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		jwk := &jose.JSONWebKey{
			Key:       priv,
			KeyID:     "test-key-1",
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		}

		proofer, err := NewProofer(jwk)
		assert.NoError(t, err)
		assert.NotNil(t, proofer)
		assert.Equal(t, jose.EdDSA, proofer.alg)

		// Verify public key
		pubJWK := proofer.key.Public()
		assert.Equal(t, pub, pubJWK.Key)

		// Test valid RSA key with proofer
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		rsaJWK := &jose.JSONWebKey{
			Key:       rsaKey,
			KeyID:     "test-key-2",
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}

		proofer, err = NewProofer(rsaJWK)
		assert.NoError(t, err)
		assert.NotNil(t, proofer)
		assert.Equal(t, jose.RS256, proofer.alg)

		// Test invalid key type
		invalidJWK := &jose.JSONWebKey{
			Key:       "invalid key",
			KeyID:     "test-key-3",
			Algorithm: "invalid",
			Use:       "sig",
		}

		_, err = NewProofer(invalidJWK)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidKey, err)
	})
}
