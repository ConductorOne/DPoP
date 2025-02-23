// Package xjwt provides JWT-related utilities.
package xjwt

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
)

// NonceSource represents a function that generates random nonces.
type NonceSource func(context.Context) (string, error)

// RandomNonce provides a cryptographically secure random nonce generator.
type RandomNonce struct {
	// Size is the number of random bytes to generate.
	// If Size is 0, a default of 16 bytes (128 bits) is used.
	Size int

	// Encoding determines how the random bytes are encoded.
	// If nil, hex encoding is used.
	Encoding *RandomEncoding
}

// Nonce returns a cryptographically secure random string.
func (rn *RandomNonce) Nonce(ctx context.Context) (string, error) {
	size := rn.Size
	if size == 0 {
		size = 16 // 128 bits of entropy
	}

	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate random nonce: %w", err)
	}

	encoding := rn.Encoding
	if encoding == nil {
		encoding = rawURL
	}

	return encoding.Generate(size)
}

// NewBase64URLRandomNonce creates a new RandomNonce that uses base64url encoding.
func NewRandomNonce() *RandomNonce {
	return &RandomNonce{
		Size:     16,
		Encoding: rawURL,
	}
}

type RandomEncoding struct {
	chars string
	clen  uint8
}

func NewRandomEncoding(chars string) *RandomEncoding {
	return &RandomEncoding{chars, uint8(len(chars))} //nolint:gosec // conversion is safe
}

// URL Safe characters
var rawURL = NewRandomEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

// Generate produces a random string of the specified size using the encoding's character set.
// It maintains uniform distribution while being more efficient by calculating the optimal buffer size.
func (e RandomEncoding) Generate(size int) (string, error) {
	rv := strings.Builder{}
	rv.Grow(size)

	// Calculate how many random bytes we need for desired output size
	// We use 1.3 as a safety factor to reduce likelihood of needing a second read
	bufSize := int(float64(size) * 1.3)
	mod := uint8(255) / e.clen * e.clen
	buf := make([]byte, bufSize)

	for rv.Len() < size {
		_, err := rand.Read(buf)
		if err != nil {
			return "", fmt.Errorf("failed to read random bytes: %w", err)
		}

		for _, v := range buf {
			// Skip bytes that would create modulo bias
			if v >= mod {
				continue
			}
			// Map the byte to our character set
			_ = rv.WriteByte(e.chars[v%e.clen])
			if rv.Len() == size {
				break
			}
		}
	}
	return rv.String(), nil
}
