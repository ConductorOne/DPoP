package jti_store_redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	// DefaultJTITTL is the default time-to-live for JTI entries
	DefaultJTITTL = 5 * time.Minute
)

var (
	// ErrJTIAlreadyUsed indicates the JTI has already been used
	ErrJTIAlreadyUsed = errors.New("jti already used")
	// ErrInvalidTTL indicates the TTL value is invalid
	ErrInvalidTTL = errors.New("ttl must be positive")
)

// JTIStore implements JTI replay protection using Redis
type JTIStore struct {
	client *redis.Client
	logger *zap.Logger
	ttl    time.Duration
}

// Option is a functional option for configuring JTIStore
type Option func(*JTIStore) error

// WithTTL sets the TTL for JTI entries
func WithTTL(ttl time.Duration) Option {
	return func(s *JTIStore) error {
		if ttl <= 0 {
			return ErrInvalidTTL
		}
		s.ttl = ttl
		return nil
	}
}

// WithLogger sets the logger for the JTIStore
func WithLogger(logger *zap.Logger) Option {
	return func(s *JTIStore) error {
		s.logger = logger
		return nil
	}
}

// NewJTIStore creates a new Redis-backed JTI store
func NewJTIStore(client *redis.Client, opts ...Option) (*JTIStore, error) {
	s := &JTIStore{
		client: client,
		logger: zap.NewNop(), // Default to no-op logger
		ttl:    DefaultJTITTL,
	}

	// Apply options
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	return s, nil
}

// hashKey creates a fixed-length hash of the input string
func hashKey(input string) string {
	h := sha256.New()
	h.Write([]byte(input))
	return hex.EncodeToString(h.Sum(nil))
}

// CheckAndStoreJTI validates and stores a JTI with a nonce
func (s *JTIStore) CheckAndStoreJTI(ctx context.Context, jti string, nonce string) error {
	// Create a single composite key from both values
	compositeKey := fmt.Sprintf("dpop:jti:%s:%s", hashKey(nonce), hashKey(jti))

	// Try to SET with NX (only if not exists) and a TTL
	ok, err := s.client.SetNX(ctx, compositeKey, "1", s.ttl).Result()
	if err != nil {
		return fmt.Errorf("redis error: %w", err)
	}

	if !ok {
		s.logger.Warn("jti reuse attempt detected",
			zap.String("jti", jti),
			zap.String("nonce", nonce),
		)
		return ErrJTIAlreadyUsed
	}

	return nil
}
