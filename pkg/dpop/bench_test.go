package dpop

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

func generateEd25519Key(b testing.TB) *jose.JSONWebKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	return &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key-ed25519",
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}
}

func generateRSAKey(b testing.TB) *jose.JSONWebKey {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	return &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key-rsa",
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
}

func generateP256Key(b testing.TB) *jose.JSONWebKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	return &jose.JSONWebKey{
		Key:       priv,
		KeyID:     "test-key-p256",
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
}

// generateNonce creates a unique nonce for each benchmark iteration
func generateNonce(i int) string {
	return fmt.Sprintf("test-nonce-%d", i)
}

func BenchmarkKeyComparison(b *testing.B) {
	ctx := context.Background()
	method := "POST"
	url := "https://api.example.com/token"

	// Generate keys once outside the benchmark
	ed25519Key := generateEd25519Key(b)
	rsaKey := generateRSAKey(b)
	p256Key := generateP256Key(b)

	// Create proofers
	ed25519Proofer, err := NewProofer(ed25519Key)
	require.NoError(b, err)
	rsaProofer, err := NewProofer(rsaKey)
	require.NoError(b, err)
	p256Proofer, err := NewProofer(p256Key)
	require.NoError(b, err)

	// Create validators
	ed25519Validator := NewValidator(
		WithJTIStore(noopJTIStore),
		WithNonceValidator(func(ctx context.Context, n string) error {
			return nil // Accept any nonce for benchmarking
		}))
	rsaValidator := NewValidator(
		WithJTIStore(noopJTIStore),
		WithNonceValidator(func(ctx context.Context, n string) error {
			return nil // Accept any nonce for benchmarking
		}))
	p256Validator := NewValidator(
		WithJTIStore(noopJTIStore),
		WithNonceValidator(func(ctx context.Context, n string) error {
			return nil // Accept any nonce for benchmarking
		}))

	// Benchmark proof generation
	b.Run("ProofGeneration/Ed25519", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			nonce := generateNonce(i)
			_, err := ed25519Proofer.CreateProof(ctx, method, url, WithStaticNonce(nonce))
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ProofGeneration/RSA2048", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			nonce := generateNonce(i)
			_, err := rsaProofer.CreateProof(ctx, method, url, WithStaticNonce(nonce))
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ProofGeneration/P256", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			nonce := generateNonce(i)
			_, err := p256Proofer.CreateProof(ctx, method, url, WithStaticNonce(nonce))
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	// Generate sample proofs for validation benchmarks
	ed25519Proof, err := ed25519Proofer.CreateProof(ctx, method, url, WithStaticNonce("test-nonce"))
	require.NoError(b, err)
	rsaProof, err := rsaProofer.CreateProof(ctx, method, url, WithStaticNonce("test-nonce"))
	require.NoError(b, err)
	p256Proof, err := p256Proofer.CreateProof(ctx, method, url, WithStaticNonce("test-nonce"))
	require.NoError(b, err)

	// Benchmark proof validation
	b.Run("ProofValidation/Ed25519", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := ed25519Validator.ValidateProof(ctx, ed25519Proof, method, url)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ProofValidation/RSA2048", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := rsaValidator.ValidateProof(ctx, rsaProof, method, url)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ProofValidation/P256", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := p256Validator.ValidateProof(ctx, p256Proof, method, url)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkProofer(b *testing.B) {
	ctx := context.Background()
	key := generateEd25519Key(b)
	proofer, err := NewProofer(key)
	if err != nil {
		b.Fatal(err)
	}

	method := "POST"
	url := "https://api.example.com/token"
	accessToken := "example-access-token"

	b.Run("BasicProof", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			nonce := generateNonce(i)
			_, err := proofer.CreateProof(ctx, method, url,
				WithStaticNonce(nonce))
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ProofWithAccessToken", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			nonce := generateNonce(i)
			_, err := proofer.CreateProof(ctx, method, url,
				WithAccessToken(accessToken),
				WithStaticNonce(nonce))
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ProofWithNonce", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			nonce := generateNonce(i)
			_, err := proofer.CreateProof(ctx, method, url,
				WithStaticNonce(nonce))
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ProofWithAllOptions", func(b *testing.B) {
		additionalClaims := map[string]interface{}{
			"custom_claim": "test-value",
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			nonce := generateNonce(i)
			_, err := proofer.CreateProof(ctx, method, url,
				WithAccessToken(accessToken),
				WithStaticNonce(nonce),
				WithAdditionalClaims(additionalClaims),
				WithValidityDuration(time.Minute))
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// noopJTIStore is a no-op JTI store for benchmarking
func noopJTIStore(ctx context.Context, jti string) error {
	return nil
}

func BenchmarkValidator(b *testing.B) {
	ctx := context.Background()
	key := generateEd25519Key(b)
	proofer, err := NewProofer(key)
	if err != nil {
		b.Fatal(err)
	}

	method := "POST"
	url := "https://api.example.com/token"
	accessToken := "example-access-token"

	// Create a validator
	validator := NewValidator(
		WithJTIStore(noopJTIStore),
		WithNonceValidator(func(ctx context.Context, n string) error {
			return nil // Accept any nonce for benchmarking
		}))

	// Create a proof with access token
	proofWithToken, err := proofer.CreateProof(ctx, method, url,
		WithAccessToken(accessToken),
		WithStaticNonce("test-nonce"),
		WithValidityDuration(time.Minute))
	if err != nil {
		b.Fatal(err)
	}

	// Create a proof without access token
	proofWithoutToken, err := proofer.CreateProof(ctx, method, url,
		WithStaticNonce("test-nonce"),
		WithValidityDuration(time.Minute))
	if err != nil {
		b.Fatal(err)
	}

	b.Run("ValidateProofWithAccessToken", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := validator.ValidateProof(ctx, proofWithToken, method, url,
				WithProofExpectedAccessToken(accessToken))
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ValidateProofWithoutAccessToken", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := validator.ValidateProof(ctx, proofWithoutToken, method, url)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ValidateProofWithPublicKey", func(b *testing.B) {
		pubKey := key.Public()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := validator.ValidateProof(ctx, proofWithToken, method, url,
				WithProofExpectedAccessToken(accessToken),
				WithProofExpectedPublicKey(&pubKey))
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ValidateProofWithConfirmationClaims", func(b *testing.B) {
		pubKey := key.Public()
		thumbprint, err := pubKey.Thumbprint(crypto.SHA256)
		if err != nil {
			b.Fatal(err)
		}
		jkt := base64.RawURLEncoding.EncodeToString(thumbprint)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := validator.ValidateProof(ctx, proofWithToken, method, url,
				WithProofExpectedAccessToken(accessToken),
				WithProofConfirmationClaims(map[string]string{
					"jkt": jkt,
				}))
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
