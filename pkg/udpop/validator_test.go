package udpop

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// CreateUnsecuredJWT creates a JWT with the 'none' algorithm for testing purposes ONLY.
func createUnsecuredJWT(t *testing.T, claims *DPoPClaims) string {
	// Step 1: Create the header with the 'none' algorithm
	header := map[string]interface{}{
		"alg": "none",
		"typ": DPoPHeaderTyp,
	}

	// Step 2: Encode the header and payload to Base64 URL-encoded JSON
	headerJSON, err := json.Marshal(header)
	require.NoError(t, err)
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)

	payloadJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Step 3: Concatenate the three JWT parts (header, payload, empty signature)
	return strings.Join([]string{headerEncoded, payloadEncoded, ""}, ".")
}

func TestValidate(t *testing.T) {
	ctx := context.Background()
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	signer, err := NewDPoPProofer(privKey)
	require.NoError(t, err)
	getProof := func(method, uri, accessToken, nonce string) string {
		proof, err := signer.Proof(method, uri, accessToken, nonce)
		require.NoError(t, err)
		return proof
	}

	getCustomProof := func(customPrivKey crypto.PrivateKey, typ string, embedJwk bool, claims *DPoPClaims) string {
		opts := &jose.SignerOptions{
			EmbedJWK: embedJwk,
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"typ": typ,
			},
		}

		var alg jose.SignatureAlgorithm
		switch customPrivKey.(type) {
		case string:
			customPrivKey = nil
			alg = "none"
		case *rsa.PrivateKey:
			alg = jose.RS256
		case ed25519.PrivateKey:
			alg = jose.EdDSA
		default:
			require.Fail(t, "invalid private key type")
			return ""
		}

		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: customPrivKey}, opts)
		require.NoError(t, err)

		proof, err := jwt.Signed(signer).Claims(claims).Serialize()
		require.NoError(t, err)

		return proof
	}

	defaultRequestMethod := http.MethodGet
	defaultRequestURI := "https://example.com/resource"

	defaultAccessTokenValidationConfig := func(accessToken string, boundPublicKey crypto.PublicKey) *DPoPAccessTokenValidationConfig {
		pubJWK := jose.JSONWebKey{Key: boundPublicKey}
		pubJWKBytes, err := pubJWK.MarshalJSON()
		require.NoError(t, err)
		return &DPoPAccessTokenValidationConfig{
			AccessToken:                  accessToken,
			AccessTokenConfirmationClaim: map[string]string{"jkt": sha256AndBase64UrlEncode(pubJWKBytes)},
		}
	}

	defaultValidationConfig := func(accessTokenConfig *DPoPAccessTokenValidationConfig, nonce string) *DPoPValidationConfig {
		uri, err := url.Parse(defaultRequestURI)
		require.NoError(t, err)
		return &DPoPValidationConfig{
			Method:                 defaultRequestMethod,
			URI:                    uri,
			AccessToken:            accessTokenConfig,
			Nonce:                  nonce,
			IssuedAtWithinDuration: time.Second * 10,
			AllowedAlgorithms:      []jose.SignatureAlgorithm{jose.EdDSA},
		}
	}

	tests := []struct {
		name              string
		headers           http.Header
		config            *DPoPValidationConfig
		expectError       bool
		expectErrorString string
	}{
		{
			name: "dpop header not found",
			headers: http.Header{
				"Authentication": {"DPoP some_token"},
			},
			config:            defaultValidationConfig(nil, ""),
			expectError:       true,
			expectErrorString: "dpop header not found",
		},
		{
			name: "multiple dpop headers found 1",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "", ""), getProof(defaultRequestMethod, defaultRequestURI, "", "")},
			},
			config:            defaultValidationConfig(nil, ""),
			expectError:       true,
			expectErrorString: "multiple dpop headers found",
		},
		{
			name: "multiple dpop headers found 2",
			headers: http.Header{
				"dpop": {getProof(defaultRequestMethod, defaultRequestURI, "", "")},
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "", "")},
			},
			config:            defaultValidationConfig(nil, ""),
			expectError:       true,
			expectErrorString: "multiple dpop headers found",
		},
		{
			name: "illegal base64 data at input byte 8",
			headers: http.Header{
				"DPoP": {"bad_proof.bad_proof.bad_proof"},
			},
			config:            defaultValidationConfig(nil, ""),
			expectError:       true,
			expectErrorString: "illegal base64 data at input byte 8",
		},
		{
			name: "config is required",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "", "")},
			},
			config:            nil,
			expectError:       true,
			expectErrorString: "config is required",
		},
		{
			name: "config.Method is required",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "", "")},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				c.Method = ""
				return c
			}(),
			expectError:       true,
			expectErrorString: "config.Method is required",
		},
		{
			name: "invalid htm",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "", "")},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				c.Method = http.MethodPost
				return c
			}(),
			expectError:       true,
			expectErrorString: "invalid htm",
		},
		{
			name: "config.URI is required",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "", "")},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				c.URI = nil
				return c
			}(),
			expectError:       true,
			expectErrorString: "config.URI is required",
		},
		{
			name: "invalid htu",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "", "")},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				uri, err := url.Parse("https://example.com/other_resource")
				require.NoError(t, err)
				c.URI = uri
				return c
			}(),
			expectError:       true,
			expectErrorString: "invalid htu",
		},
		{
			name: "config.AllowedAlgorithms must be exactly [EdDSA] 1",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "", "")},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				c.AllowedAlgorithms = nil
				return c
			}(),
			expectError:       true,
			expectErrorString: "config.AllowedAlgorithms must be exactly [EdDSA]",
		},
		{
			name: "config.AllowedAlgorithms must be exactly [EdDSA] 2",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "", "")},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				c.AllowedAlgorithms = []jose.SignatureAlgorithm{jose.HS512, jose.EdDSA}
				return c
			}(),
			expectError:       true,
			expectErrorString: "config.AllowedAlgorithms must be exactly [EdDSA]",
		},
		{
			name: "config.IssuedAtWithinDuration must be greater than 0 and less than 5m",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "", "")},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				c.IssuedAtWithinDuration = 0
				return c
			}(),
			expectError:       true,
			expectErrorString: "config.IssuedAtWithinDuration must be greater than 0 and less than 5m",
		},
		{
			name: "config.IssuedAtWithinDuration must be greater than 0 and less than 5m 2",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "", "")},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				c.IssuedAtWithinDuration = time.Hour
				return c
			}(),
			expectError:       true,
			expectErrorString: "config.IssuedAtWithinDuration must be greater than 0 and less than 5m",
		},
		{
			name: "config.Nonce is required",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "", "some_nonce")},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				return c
			}(),
			expectError:       true,
			expectErrorString: "config.Nonce is required",
		},
		{
			name: "invalid nonce",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "", "some_nonce")},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "different_nonce")
				return c
			}(),
			expectError:       true,
			expectErrorString: "invalid nonce",
		},
		{
			name: "missing nonce",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "", "")},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "some_nonce")
				return c
			}(),
			expectError:       true,
			expectErrorString: "missing nonce",
		},
		{
			name: "config.AccessToken is required",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "some_token", "")},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				return c
			}(),
			expectError:       true,
			expectErrorString: "config.AccessToken is required",
		},
		{
			name: "config.AccessToken is required 2",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "some_token", "")},
			},
			config: func() *DPoPValidationConfig {
				ath := defaultAccessTokenValidationConfig("", pubKey)
				c := defaultValidationConfig(ath, "")
				return c
			}(),
			expectError:       true,
			expectErrorString: "config.AccessToken is required",
		},
		{
			name: "missing ath",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "", "")},
			},
			config: func() *DPoPValidationConfig {
				atc := defaultAccessTokenValidationConfig("some_token", pubKey)
				c := defaultValidationConfig(atc, "")
				return c
			}(),
			expectError:       true,
			expectErrorString: "missing ath",
		},
		{
			name: "invalid ath",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "some_token", "")},
			},
			config: func() *DPoPValidationConfig {
				atc := defaultAccessTokenValidationConfig("different_token", pubKey)
				c := defaultValidationConfig(atc, "")
				return c
			}(),
			expectError:       true,
			expectErrorString: "invalid ath",
		},
		{
			name: "proof pubkey does not match bound pubkey",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "some_token", "")},
			},
			config: func() *DPoPValidationConfig {
				rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				atc := defaultAccessTokenValidationConfig("some_token", &rsaKey.PublicKey)
				c := defaultValidationConfig(atc, "")
				return c
			}(),
			expectError:       true,
			expectErrorString: "proof pubkey does not match bound pubkey",
		},
		{
			name: "proof pubkey does not match bound pubkey 2",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "some_token", "")},
			},
			config: func() *DPoPValidationConfig {
				differentPubKey, _, err := ed25519.GenerateKey(nil)
				require.NoError(t, err)
				atc := defaultAccessTokenValidationConfig("some_token", differentPubKey)
				c := defaultValidationConfig(atc, "")
				return c
			}(),
			expectError:       true,
			expectErrorString: "proof pubkey does not match bound pubkey",
		},
		{
			name: "valid proof w/ath",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "some_token", "")},
			},
			config: func() *DPoPValidationConfig {
				pubKeyCopy := ed25519.PublicKey{}
				copy(pubKeyCopy, pubKey)
				atc := defaultAccessTokenValidationConfig("some_token", pubKey)
				c := defaultValidationConfig(atc, "")
				return c
			}(),
			expectError: false,
		},
		{
			name: "valid proof w/URI normalized",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "", "")},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				uri, err := url.Parse("HTTPS://example.com/resource?query=1#fragment")
				require.NoError(t, err)
				c.URI = uri
				return c
			}(),
			expectError: false,
		},
		{
			name: "valid proof w/nonce",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "", "some_nonce")},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "some_nonce")
				return c
			}(),
			expectError: false,
		},
		{
			name: "valid proof",
			headers: http.Header{
				"DPoP": {getProof(defaultRequestMethod, defaultRequestURI, "", "")},
			},
			config:      defaultValidationConfig(nil, ""),
			expectError: false,
		},
		{
			name: "header: invalid typ",
			headers: http.Header{
				"DPoP": {getCustomProof(privKey, "other_typ", true, &DPoPClaims{
					Claims: &jwt.Claims{
						IssuedAt: nil,
						ID:       uuid.Must(uuid.NewRandom()).String(),
					},
					Htm:   defaultRequestMethod,
					Htu:   defaultRequestURI,
					Ath:   "",
					Nonce: "",
				})},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "some_nonce")
				return c
			}(),
			expectError:       true,
			expectErrorString: "header: invalid typ",
		},
		{
			name: "header: missing jwk",
			headers: http.Header{
				"DPoP": {func() string {
					return getCustomProof(privKey, DPoPHeaderTyp, false, &DPoPClaims{
						Claims: &jwt.Claims{
							IssuedAt: jwt.NewNumericDate(time.Now()),
							ID:       uuid.Must(uuid.NewRandom()).String(),
						},
						Htm:   defaultRequestMethod,
						Htu:   defaultRequestURI,
						Ath:   "",
						Nonce: "",
					})
				}(),
				},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				return c
			}(),
			expectError:       true,
			expectErrorString: "header: missing jwk",
		},
		{
			name: "unexpected signature algorithm \"none\"",
			headers: http.Header{
				"DPoP": {func() string {
					claims := &DPoPClaims{
						Claims: &jwt.Claims{
							IssuedAt: jwt.NewNumericDate(time.Now()),
							ID:       uuid.Must(uuid.NewRandom()).String(),
						},
						Htm:   defaultRequestMethod,
						Htu:   defaultRequestURI,
						Ath:   "",
						Nonce: "",
					}
					return createUnsecuredJWT(t, claims)
				}(),
				},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				return c
			}(),
			expectError:       true,
			expectErrorString: "unexpected signature algorithm \"none\"",
		},
		{
			name: "claims: missing jti",
			headers: http.Header{
				"DPoP": {func() string {
					return getCustomProof(privKey, DPoPHeaderTyp, true, &DPoPClaims{
						Claims: &jwt.Claims{
							IssuedAt: jwt.NewNumericDate(time.Now()),
							ID:       "",
						},
						Htm:   defaultRequestMethod,
						Htu:   defaultRequestURI,
						Ath:   "",
						Nonce: "",
					})
				}(),
				},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				return c
			}(),
			expectError:       true,
			expectErrorString: "claims: missing jti",
		},
		{
			name: "claims: missing htm",
			headers: http.Header{
				"DPoP": {func() string {
					return getCustomProof(privKey, DPoPHeaderTyp, true, &DPoPClaims{
						Claims: &jwt.Claims{
							IssuedAt: jwt.NewNumericDate(time.Now()),
							ID:       uuid.Must(uuid.NewRandom()).String(),
						},
						Htm:   "",
						Htu:   defaultRequestURI,
						Ath:   "",
						Nonce: "",
					})
				}(),
				},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				return c
			}(),
			expectError:       true,
			expectErrorString: "claims: missing htm",
		},
		{
			name: "claims: malformed htm: OTHER",
			headers: http.Header{
				"DPoP": {func() string {
					return getCustomProof(privKey, DPoPHeaderTyp, true, &DPoPClaims{
						Claims: &jwt.Claims{
							IssuedAt: jwt.NewNumericDate(time.Now()),
							ID:       uuid.Must(uuid.NewRandom()).String(),
						},
						Htm:   "OTHER",
						Htu:   defaultRequestURI,
						Ath:   "",
						Nonce: "",
					})
				}(),
				},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				return c
			}(),
			expectError:       true,
			expectErrorString: "claims: malformed htm: OTHER",
		},
		{
			name: "claims: missing htu",
			headers: http.Header{
				"DPoP": {func() string {
					return getCustomProof(privKey, DPoPHeaderTyp, true, &DPoPClaims{
						Claims: &jwt.Claims{
							IssuedAt: jwt.NewNumericDate(time.Now()),
							ID:       uuid.Must(uuid.NewRandom()).String(),
						},
						Htm:   defaultRequestMethod,
						Htu:   "",
						Ath:   "",
						Nonce: "",
					})
				}(),
				},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				return c
			}(),
			expectError:       true,
			expectErrorString: "claims: missing htu",
		},
		{
			name: "claims: valid proof w/URI normalized",
			headers: http.Header{
				"DPoP": {func() string {
					return getCustomProof(privKey, DPoPHeaderTyp, true, &DPoPClaims{
						Claims: &jwt.Claims{
							IssuedAt: jwt.NewNumericDate(time.Now()),
							ID:       uuid.Must(uuid.NewRandom()).String(),
						},
						Htm:   defaultRequestMethod,
						Htu:   "https://example.com?query=1#fragment",
						Ath:   "",
						Nonce: "",
					})
				}(),
				},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				c.URI, err = url.Parse("HTTPS://example.com/")
				require.NoError(t, err)
				return c
			}(),
			expectError: false,
		},
		{
			name: "claims: valid proof w/URI normalized",
			headers: http.Header{
				"DPoP": {func() string {
					return getCustomProof(privKey, DPoPHeaderTyp, true, &DPoPClaims{
						Claims: &jwt.Claims{
							IssuedAt: jwt.NewNumericDate(time.Now()),
							ID:       uuid.Must(uuid.NewRandom()).String(),
						},
						Htm:   defaultRequestMethod,
						Htu:   "https://example.com/resource?query=1#fragment",
						Ath:   "",
						Nonce: "",
					})
				}(),
				},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				return c
			}(),
			expectError: false,
		},
		{
			name: "claims: missing iat",
			headers: http.Header{
				"DPoP": {func() string {
					return getCustomProof(privKey, DPoPHeaderTyp, true, &DPoPClaims{
						Claims: &jwt.Claims{
							IssuedAt: nil,
							ID:       uuid.Must(uuid.NewRandom()).String(),
						},
						Htm:   defaultRequestMethod,
						Htu:   defaultRequestURI,
						Ath:   "",
						Nonce: "",
					})
				}(),
				},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				return c
			}(),
			expectError:       true,
			expectErrorString: "claims: missing iat",
		},
		{
			name: "claims: invalid iat, before expected range",
			headers: http.Header{
				"DPoP": {func() string {
					return getCustomProof(privKey, DPoPHeaderTyp, true, &DPoPClaims{
						Claims: &jwt.Claims{
							IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute * 5)),
							ID:       uuid.Must(uuid.NewRandom()).String(),
						},
						Htm:   defaultRequestMethod,
						Htu:   defaultRequestURI,
						Ath:   "",
						Nonce: "",
					})
				}(),
				},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				return c
			}(),
			expectError:       true,
			expectErrorString: "claims: invalid iat, before expected range",
		},
		{
			name: "claims: invalid iat, after expected range",
			headers: http.Header{
				"DPoP": {func() string {
					return getCustomProof(privKey, DPoPHeaderTyp, true, &DPoPClaims{
						Claims: &jwt.Claims{
							IssuedAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 5)),
							ID:       uuid.Must(uuid.NewRandom()).String(),
						},
						Htm:   defaultRequestMethod,
						Htu:   defaultRequestURI,
						Ath:   "",
						Nonce: "",
					})
				}(),
				},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				return c
			}(),
			expectError:       true,
			expectErrorString: "claims: invalid iat, after expected range",
		},
		{
			name: "malformed htu: parse \"://example.com/resource\": missing protocol scheme",
			headers: http.Header{
				"DPoP": {func() string {
					return getCustomProof(privKey, DPoPHeaderTyp, true, &DPoPClaims{
						Claims: &jwt.Claims{
							IssuedAt: jwt.NewNumericDate(time.Now()),
							ID:       uuid.Must(uuid.NewRandom()).String(),
						},
						Htm:   defaultRequestMethod,
						Htu:   "://example.com/resource",
						Ath:   "",
						Nonce: "",
					})
				}(),
				},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(nil, "")
				return c
			}(),
			expectError:       true,
			expectErrorString: "malformed htu: parse \"://example.com/resource\": missing protocol scheme",
		},
		{
			name: "claims: invalid ath",
			headers: http.Header{
				"DPoP": {func() string {
					require.NoError(t, err)
					return getCustomProof(privKey, DPoPHeaderTyp, true, &DPoPClaims{
						Claims: &jwt.Claims{
							IssuedAt: jwt.NewNumericDate(time.Now()),
							ID:       uuid.Must(uuid.NewRandom()).String(),
						},
						Htm:   defaultRequestMethod,
						Htu:   defaultRequestURI,
						Ath:   sha256AndBase64UrlEncode([]byte("")),
						Nonce: "",
					})
				}(),
				},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(defaultAccessTokenValidationConfig("", pubKey), "")
				return c
			}(),
			expectError:       true,
			expectErrorString: "claims: invalid ath",
		},
		{
			name: "proof pubkey does not match bound pubkey",
			headers: http.Header{
				"DPoP": {func() string {
					_, differentPrivKey, err := ed25519.GenerateKey(nil)
					require.NoError(t, err)
					return getCustomProof(differentPrivKey, DPoPHeaderTyp, true, &DPoPClaims{
						Claims: &jwt.Claims{
							IssuedAt: jwt.NewNumericDate(time.Now()),
							ID:       uuid.Must(uuid.NewRandom()).String(),
						},
						Htm:   defaultRequestMethod,
						Htu:   defaultRequestURI,
						Ath:   sha256AndBase64UrlEncode([]byte("some_token")),
						Nonce: "",
					})
				}(),
				},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(defaultAccessTokenValidationConfig("some_token", pubKey), "")
				return c
			}(),
			expectError:       true,
			expectErrorString: "proof pubkey does not match bound pubkey",
		},
		{
			name: "unexpected signature algorithm \"RS256\"; expected [\"EdDSA\"]",
			headers: http.Header{
				"DPoP": {func() string {
					differentPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
					require.NoError(t, err)
					return getCustomProof(differentPrivKey, DPoPHeaderTyp, true, &DPoPClaims{
						Claims: &jwt.Claims{
							IssuedAt: jwt.NewNumericDate(time.Now()),
							ID:       uuid.Must(uuid.NewRandom()).String(),
						},
						Htm:   defaultRequestMethod,
						Htu:   defaultRequestURI,
						Ath:   sha256AndBase64UrlEncode([]byte("some_token")),
						Nonce: "",
					})
				}(),
				},
			},
			config: func() *DPoPValidationConfig {
				c := defaultValidationConfig(defaultAccessTokenValidationConfig("some_token", pubKey), "")
				return c
			}(),
			expectError:       true,
			expectErrorString: "unexpected signature algorithm \"RS256\"; expected [\"EdDSA\"]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proofPubKey, err := Validate(ctx, tt.headers, tt.config)
			if !tt.expectError {
				require.NoError(t, err)
				require.True(t, pubKey.Equal(proofPubKey.Key))
				return
			}
			require.Nil(t, proofPubKey)
			require.Error(t, err)
			require.True(t, errors.Is(err, ErrProofInvalid))
			require.Contains(t, err.Error(), tt.expectErrorString)
		})
	}
}
