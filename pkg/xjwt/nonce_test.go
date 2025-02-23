package xjwt

import (
	"context"
	"strings"
	"testing"
)

func TestRandomNonce(t *testing.T) {
	tests := []struct {
		name    string
		nonce   *RandomNonce
		wantLen int
		chars   string
	}{
		{
			name:    "default settings",
			nonce:   NewRandomNonce(),
			wantLen: 16,
			chars:   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
		},
		{
			name: "custom size",
			nonce: &RandomNonce{
				Size:     32,
				Encoding: rawURL,
			},
			wantLen: 32,
			chars:   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
		},
		{
			name: "custom encoding",
			nonce: &RandomNonce{
				Size:     16,
				Encoding: NewRandomEncoding("0123456789abcdef"),
			},
			wantLen: 16,
			chars:   "0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate multiple nonces to ensure they're unique
			seen := make(map[string]bool)
			for i := 0; i < 100; i++ {
				nonce, err := tt.nonce.Nonce(context.Background())
				if err != nil {
					t.Fatalf("Nonce() error = %v", err)
				}

				// Check length
				if len(nonce) != tt.wantLen {
					t.Errorf("Nonce() length = %v, want %v", len(nonce), tt.wantLen)
				}

				// Check uniqueness
				if seen[nonce] {
					t.Errorf("Nonce() generated duplicate value: %v", nonce)
				}
				seen[nonce] = true

				// Verify only allowed characters are used
				for _, c := range nonce {
					if !strings.ContainsRune(tt.chars, c) {
						t.Errorf("Nonce() contains invalid character: %c", c)
					}
				}
			}
		})
	}
}

func TestRandomNonceInterface(t *testing.T) {
	var _ NonceSource = (*RandomNonce)(nil).Nonce
}
