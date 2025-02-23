package dpop

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKnownJWTClaimsFields verifies that we haven't missed any fields from jwt.Claims
func TestKnownJWTClaimsFields(t *testing.T) {
	// Get all fields from jwt.Claims struct
	claimsType := reflect.TypeOf(jwt.Claims{})
	actualFields := make(map[string]bool)
	for i := 0; i < claimsType.NumField(); i++ {
		field := claimsType.Field(i)
		if jsonTag := field.Tag.Get("json"); jsonTag != "" {
			// Split the json tag to get the field name (before any comma)
			fieldName := jsonTag
			if comma := strings.Index(jsonTag, ","); comma != -1 {
				fieldName = jsonTag[:comma]
			}
			actualFields[fieldName] = true
		}
	}

	// Verify all known fields are present in jwt.Claims
	for _, field := range knownJWTClaimsFields {
		assert.True(t, actualFields[field], "Field %s is in knownJWTClaimsFields but not in jwt.Claims", field)
		delete(actualFields, field)
	}

	// Verify no fields are missing from knownJWTClaimsFields
	assert.Empty(t, actualFields, "Fields %v are in jwt.Claims but not in knownJWTClaimsFields", actualFields)
}

func TestClaimsMarshalJSON(t *testing.T) {
	now := time.Now()
	claims := &Claims{
		Claims: &jwt.Claims{
			Issuer:    "test-issuer",
			Subject:   "test-subject",
			Audience:  jwt.Audience{"test-audience"},
			Expiry:    jwt.NewNumericDate(now.Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "test-id",
		},
		HTTPMethod: "POST",
		HTTPUri:    "https://example.com/resource",
		TokenHash:  "test-hash",
		Nonce:      "test-nonce",
		Additional: map[string]interface{}{
			"custom_claim": "custom_value",
			"iss":          "should-not-override", // Should not override standard claim
		},
	}

	// Marshal the claims
	data, err := json.Marshal(claims)
	require.NoError(t, err)

	// Unmarshal into a map to verify the contents
	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Verify standard JWT claims
	assert.Equal(t, "test-issuer", result["iss"])
	assert.Equal(t, "test-subject", result["sub"])
	assert.Equal(t, "test-audience", result["aud"])
	assert.NotNil(t, result["exp"])
	assert.NotNil(t, result["nbf"])
	assert.NotNil(t, result["iat"])
	assert.Equal(t, "test-id", result["jti"])

	// Verify DPoP specific claims
	assert.Equal(t, "POST", result["htm"])
	assert.Equal(t, "https://example.com/resource", result["htu"])
	assert.Equal(t, "test-hash", result["ath"])
	assert.Equal(t, "test-nonce", result["nonce"])

	// Verify additional claims
	assert.Equal(t, "custom_value", result["custom_claim"])

	// Unmarshal back into Claims
	var newClaims Claims
	err = json.Unmarshal(data, &newClaims)
	require.NoError(t, err)

	// Verify the unmarshaled claims match the original
	assert.Equal(t, claims.Claims.Issuer, newClaims.Claims.Issuer)
	assert.Equal(t, claims.Claims.Subject, newClaims.Claims.Subject)
	assert.Equal(t, claims.Claims.Audience, newClaims.Claims.Audience)
	assert.Equal(t, claims.Claims.Expiry.Time().Unix(), newClaims.Claims.Expiry.Time().Unix())
	assert.Equal(t, claims.Claims.NotBefore.Time().Unix(), newClaims.Claims.NotBefore.Time().Unix())
	assert.Equal(t, claims.Claims.IssuedAt.Time().Unix(), newClaims.Claims.IssuedAt.Time().Unix())
	assert.Equal(t, claims.Claims.ID, newClaims.Claims.ID)
	assert.Equal(t, claims.HTTPMethod, newClaims.HTTPMethod)
	assert.Equal(t, claims.HTTPUri, newClaims.HTTPUri)
	assert.Equal(t, claims.TokenHash, newClaims.TokenHash)
	assert.Equal(t, claims.Nonce, newClaims.Nonce)
	assert.Equal(t, "custom_value", newClaims.Additional["custom_claim"])
}
