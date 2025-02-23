package jti_store_redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	// DefaultJTITTL is the default time-to-live for JTI entries
	DefaultJTITTL = 5 * time.Minute

	// DefaultMaxJTIsPerNonce is the maximum number of JTIs allowed per nonce
	DefaultMaxJTIsPerNonce = 10000
)

// JTIStore implements JTI replay protection using Redis
type JTIStore struct {
	client          *redis.Client
	logger          *zap.Logger
	ttl             time.Duration
	maxJTIsPerNonce int
}

// JTIStoreOption configures the JTIStore
type JTIStoreOption func(*JTIStore)

// WithTTL sets the TTL for JTI entries
func WithTTL(ttl time.Duration) JTIStoreOption {
	return func(s *JTIStore) {
		s.ttl = ttl
	}
}

// WithMaxJTIsPerNonce sets the maximum number of JTIs allowed per nonce
func WithMaxJTIsPerNonce(max int) JTIStoreOption {
	return func(s *JTIStore) {
		s.maxJTIsPerNonce = max
	}
}

// NewJTIStore creates a new Redis-backed JTI store
func NewJTIStore(client *redis.Client, logger *zap.Logger, opts ...JTIStoreOption) *JTIStore {
	s := &JTIStore{
		client:          client,
		logger:          logger,
		ttl:             DefaultJTITTL,
		maxJTIsPerNonce: DefaultMaxJTIsPerNonce,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// hashKey creates a fixed-length hash of the input string
func hashKey(input string) string {
	h := sha256.New()
	h.Write([]byte(input))
	return hex.EncodeToString(h.Sum(nil))
}

// CheckAndStoreJTI validates and stores a JTI with a nonce
func (s *JTIStore) CheckAndStoreJTI(ctx context.Context, jti string, nonce string) error {
	// Hash both values to prevent large strings from consuming memory
	jtiHash := hashKey(jti)
	nonceHash := hashKey(nonce)

	// Key format: dpop:nonce:{nonce_hash}:jti:{jti_hash}
	key := fmt.Sprintf("dpop:nonce:%s:jti:%s", nonceHash, jtiHash)
	nonceKey := fmt.Sprintf("dpop:nonce:%s:count", nonceHash)

	// Lua script for atomic check-and-set with rate limiting
	script := `
		local key = KEYS[1]
		local nonce_key = KEYS[2]
		local max_jtis = tonumber(ARGV[1])
		local ttl = tonumber(ARGV[2])

		-- Check if JTI exists
		if redis.call("EXISTS", key) == 1 then
			return {err = "jti_already_used"}
		end

		-- Check/increment nonce counter
		local count = redis.call("INCR", nonce_key)
		if count == 1 then
			-- First use of this nonce, set TTL
			redis.call("EXPIRE", nonce_key, ttl)
		elseif count > max_jtis then
			-- Too many JTIs for this nonce
			return {err = "nonce_rate_limit_exceeded"}
		end

		-- Store JTI with TTL
		redis.call("SET", key, "1", "PX", ttl)
		
		return {ok = "success"}
	`

	// Execute the Lua script
	result, err := s.client.Eval(ctx, script, []string{key, nonceKey}, s.maxJTIsPerNonce, int(s.ttl.Milliseconds())).Result()
	if err != nil {
		s.logger.Error("redis error checking jti",
			zap.String("jti", jti),
			zap.String("nonce", nonce),
			zap.Error(err),
		)
		return fmt.Errorf("redis error: %w", err)
	}

	// Parse result
	switch v := result.(type) {
	case string:
		if v == "success" {
			s.logger.Info("jti stored successfully",
				zap.String("jti", jti),
				zap.String("nonce", nonce),
			)
			return nil
		}
	}

	// If we get here, there was an error condition from Lua
	s.logger.Warn("jti validation failed",
		zap.String("jti", jti),
		zap.String("nonce", nonce),
		zap.Any("result", result),
	)

	if fmt.Sprintf("%v", result) == "jti_already_used" {
		return fmt.Errorf("jti already used")
	}
	return fmt.Errorf("nonce rate limit exceeded")
}
