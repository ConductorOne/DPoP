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
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		proofer, err := NewProofer(priv)
		assert.NoError(t, err)
		assert.NotNil(t, proofer)
		assert.Equal(t, jose.EdDSA, proofer.alg)

		// Test valid RSA key with proofer
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		proofer, err = NewProofer(rsaKey)
		assert.NoError(t, err)
		assert.NotNil(t, proofer)
		assert.Equal(t, jose.RS256, proofer.alg)

		// Test invalid key type
		_, err = NewProofer("invalid key")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidKey, err)
	})
}
