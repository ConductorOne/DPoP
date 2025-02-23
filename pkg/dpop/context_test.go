package dpop

import (
	"context"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
)

func TestClaimsContext(t *testing.T) {
	ctx := context.Background()

	t.Run("store and retrieve claims", func(t *testing.T) {
		claims := &Claims{
			Claims: &jwt.Claims{
				ID:        "test-id",
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now().Add(-30 * time.Second)),
				Expiry:    jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			},
			HTTPMethod: "GET",
			HTTPUri:    "https://resource.example.org/protected",
			Nonce:      "test-nonce",
			TokenHash:  "test-hash",
		}

		// Store claims in context
		ctxWithClaims := WithClaims(ctx, claims)
		assert.NotNil(t, ctxWithClaims)

		// Retrieve claims from context
		retrievedClaims, ok := ClaimsFromContext(ctxWithClaims)
		assert.True(t, ok)
		assert.Equal(t, claims, retrievedClaims)
	})

	t.Run("retrieve from empty context", func(t *testing.T) {
		claims, ok := ClaimsFromContext(ctx)
		assert.False(t, ok)
		assert.Nil(t, claims)
	})

	t.Run("retrieve with wrong type", func(t *testing.T) {
		// Store wrong type in context
		wrongCtx := context.WithValue(ctx, claimsContextKey, "not-claims")
		claims, ok := ClaimsFromContext(wrongCtx)
		assert.False(t, ok)
		assert.Nil(t, claims)
	})
}
