package jti_store_redis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func setupTestRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()

	// Start a mini Redis server
	mr, err := miniredis.Run()
	require.NoError(t, err)

	// Create a Redis client connected to the mini Redis server
	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	return mr, client
}

func TestNewJTIStore(t *testing.T) {
	_, client := setupTestRedis(t)
	defer client.Close()

	t.Run("Default_Options", func(t *testing.T) {
		store, err := NewJTIStore(client)
		require.NoError(t, err)
		assert.Equal(t, DefaultJTITTL, store.ttl)
		assert.NotNil(t, store.logger)
	})

	t.Run("With_Custom_TTL", func(t *testing.T) {
		customTTL := 10 * time.Minute
		store, err := NewJTIStore(client, WithTTL(customTTL))
		require.NoError(t, err)
		assert.Equal(t, customTTL, store.ttl)
	})

	t.Run("With_Invalid_TTL", func(t *testing.T) {
		_, err := NewJTIStore(client, WithTTL(-1*time.Minute))
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidTTL)
	})

	t.Run("With_Custom_Logger", func(t *testing.T) {
		logger := zap.NewExample()
		store, err := NewJTIStore(client, WithLogger(logger))
		require.NoError(t, err)
		assert.Equal(t, logger, store.logger)
	})
}

func TestCheckAndStoreJTI(t *testing.T) {
	mr, client := setupTestRedis(t)
	defer mr.Close()
	defer client.Close()

	store, err := NewJTIStore(client)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("First_Use_Succeeds", func(t *testing.T) {
		err := store.CheckAndStoreJTI(ctx, "jti-1")
		assert.NoError(t, err)
	})

	t.Run("Reuse_Fails", func(t *testing.T) {
		// First use
		err := store.CheckAndStoreJTI(ctx, "jti-2")
		assert.NoError(t, err)

		// Reuse attempt
		err = store.CheckAndStoreJTI(ctx, "jti-2")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrJTIAlreadyUsed)
	})

	t.Run("Different_JTIs_Succeed", func(t *testing.T) {
		err := store.CheckAndStoreJTI(ctx, "jti-3")
		assert.NoError(t, err)

		err = store.CheckAndStoreJTI(ctx, "jti-4")
		assert.NoError(t, err)
	})

	t.Run("Expires_After_TTL", func(t *testing.T) {
		// Use a short TTL for testing
		shortTTLStore, err := NewJTIStore(client, WithTTL(100*time.Millisecond))
		require.NoError(t, err)

		// First use
		err = shortTTLStore.CheckAndStoreJTI(ctx, "jti-ttl-test")
		assert.NoError(t, err)

		// Fast-forward time in miniredis
		mr.FastForward(200 * time.Millisecond)

		// Should succeed after TTL expiration
		err = shortTTLStore.CheckAndStoreJTI(ctx, "jti-ttl-test")
		assert.NoError(t, err)
	})
}

func TestHashKey(t *testing.T) {
	// Test that the hash function produces consistent results
	hash1 := hashKey("test-jti")
	hash2 := hashKey("test-jti")
	assert.Equal(t, hash1, hash2)

	// Test that different inputs produce different hashes
	hash3 := hashKey("different-jti")
	assert.NotEqual(t, hash1, hash3)
}
