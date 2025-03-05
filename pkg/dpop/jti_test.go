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

func TestMemoryJTIStore(t *testing.T) {
	ctx := context.Background()

	t.Run("basic store and check", func(t *testing.T) {
		store := NewMemoryJTIStore()
		defer store.Stop()

		jti := "test-jti-1"

		// First attempt should succeed
		err := store.CheckAndStoreJTI(ctx, jti)
		require.NoError(t, err)

		// Second attempt with same JTI should fail
		err = store.CheckAndStoreJTI(ctx, jti)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate jti")

		// Different JTI should succeed
		err = store.CheckAndStoreJTI(ctx, "different-jti")
		require.NoError(t, err)

		// Different JTI should fail
		err = store.CheckAndStoreJTI(ctx, "different-jti")
		require.Error(t, err)
	})

	t.Run("cache cleanup", func(t *testing.T) {
		store := NewMemoryJTIStore()
		defer store.Stop()

		// Add some entries
		for i := 0; i < 5; i++ {
			err := store.CheckAndStoreJTI(ctx, fmt.Sprintf("jti-%d", i))
			require.NoError(t, err)
		}

		// Force cleanup of expired entries
		store.cache.DeleteExpired()

		// Verify cache still has entries (they shouldn't expire yet)
		assert.Greater(t, store.cache.Len(), 0)
	})
}

func TestJTIReplayPrevention(t *testing.T) {
	// Setup test keys and validator
	_, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	jwk := &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key-1",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}

	proofer, err := NewProofer(jwk)
	require.NoError(t, err)

	store := NewMemoryJTIStore()
	defer store.Stop()
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

	t.Run("reject duplicate JTI", func(t *testing.T) {
		// Create a valid proof with nonce
		proof, err := proofer.CreateProof(
			context.Background(),
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(10*time.Minute),
			WithStaticNonce("test-nonce-1"),
		)
		require.NoError(t, err)

		// First validation should succeed
		claims, err := validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
		)
		require.NoError(t, err)
		require.NotNil(t, claims)

		// Second validation with same proof should fail
		_, err = validator.ValidateProof(
			context.Background(),
			proof,
			"GET",
			"https://resource.example.org/protected",
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate jti")
	})
}

func TestJTIHandling(t *testing.T) {
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

	t.Run("basic JTI validation", func(t *testing.T) {
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

		// Create and validate proof
		proof, err := proofer.CreateProof(
			ctx,
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(5*time.Minute),
			WithStaticNonce("test-nonce-1"),
		)
		require.NoError(t, err)

		claims, err := validator.ValidateProof(ctx, proof, "GET", "https://resource.example.org/protected")
		require.NoError(t, err)
		assert.NotEmpty(t, claims.Claims.ID)
	})

	t.Run("JTI replay prevention", func(t *testing.T) {
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

		// Create first proof with nonce
		proof, err := proofer.CreateProof(
			ctx,
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(5*time.Minute),
			WithStaticNonce("test-nonce-1"),
		)
		require.NoError(t, err)

		// First validation should succeed
		_, err = validator.ValidateProof(ctx, proof, "GET", "https://resource.example.org/protected")
		require.NoError(t, err)

		// Second validation with same proof should fail (replay attempt)
		_, err = validator.ValidateProof(ctx, proof, "GET", "https://resource.example.org/protected")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate jti")
	})

	t.Run("JTI size limits", func(t *testing.T) {
		store := NewMemoryJTIStore()
		validator := NewValidator(
			WithAllowedSignatureAlgorithms([]jose.SignatureAlgorithm{jose.EdDSA}),
			WithJTIStore(store.CheckAndStoreJTI),
		)

		// Create proof with oversized JTI
		largeJTI := strings.Repeat("x", MaxJTISize+1)

		// Create a proof with the large JTI
		key := jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}
		signer, err := jose.NewSigner(key, &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"typ": DPoPHeaderTyp,
				"jwk": &jose.JSONWebKey{
					Key:       pub,
					Algorithm: string(jose.EdDSA),
					Use:       "sig",
				},
			},
		})
		require.NoError(t, err)

		claims := &Claims{
			Claims: &jwt.Claims{
				ID:        largeJTI,
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now().Add(-30 * time.Second)),
				Expiry:    jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			},
			HTTPMethod: "GET",
			HTTPUri:    "https://resource.example.org/protected",
		}

		token, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)

		// Validation should fail due to JTI size
		_, err = validator.ValidateProof(ctx, token, "GET", "https://resource.example.org/protected")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "jti too large")
	})

	t.Run("concurrent JTI validation", func(t *testing.T) {
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

		// Create a proof to use
		proof, err := proofer.CreateProof(
			ctx,
			"GET",
			"https://resource.example.org/protected",
			WithValidityDuration(5*time.Minute),
			WithStaticNonce("test-nonce-1"),
		)
		require.NoError(t, err)

		// Run concurrent validations
		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				_, err := validator.ValidateProof(ctx, proof, "GET", "https://resource.example.org/protected")
				if err == nil {
					done <- true
				} else {
					done <- false
				}
			}()
		}

		// Only one validation should succeed
		successCount := 0
		for i := 0; i < 10; i++ {
			if <-done {
				successCount++
			}
		}
		assert.Equal(t, 1, successCount, "Only one validation should succeed")
	})
}

func TestMemoryJTIStoreOperations(t *testing.T) {
	ctx := context.Background()

	t.Run("custom TTL", func(t *testing.T) {
		store := NewMemoryJTIStoreWithOptions(&MemoryJTIStoreOptions{
			TTL: 1 * time.Second,
		})
		defer store.Stop()

		// Store a JTI
		err := store.CheckAndStoreJTI(ctx, "test-jti")
		assert.NoError(t, err)

		// Immediate check should fail (duplicate)
		err = store.CheckAndStoreJTI(ctx, "test-jti")
		assert.Error(t, err)

		// Wait for TTL to expire
		time.Sleep(2 * time.Second)

		// After TTL expires, should be able to reuse the JTI
		err = store.CheckAndStoreJTI(ctx, "test-jti")
		assert.NoError(t, err)
	})

	t.Run("default TTL", func(t *testing.T) {
		store := NewMemoryJTIStore()
		defer store.Stop()

		// Store a JTI
		err := store.CheckAndStoreJTI(ctx, "test-jti")
		assert.NoError(t, err)

		// Immediate check should fail (duplicate)
		err = store.CheckAndStoreJTI(ctx, "test-jti")
		assert.Error(t, err)
	})

	t.Run("store and check JTI", func(t *testing.T) {
		store := NewMemoryJTIStore()
		defer store.Stop()

		// First store should succeed
		err := store.CheckAndStoreJTI(ctx, "test-jti")
		assert.NoError(t, err)

		// Second store should fail
		err = store.CheckAndStoreJTI(ctx, "test-jti")
		assert.Error(t, err)
	})

	t.Run("different JTIs", func(t *testing.T) {
		store := NewMemoryJTIStore()
		defer store.Stop()

		// Store multiple different JTIs
		for i := 0; i < 5; i++ {
			err := store.CheckAndStoreJTI(ctx, fmt.Sprintf("jti-%d", i))
			assert.NoError(t, err)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		store := NewMemoryJTIStore()
		defer store.Stop()

		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()

		err := store.CheckAndStoreJTI(cancelCtx, "test-jti")
		assert.Error(t, err)
	})
}
