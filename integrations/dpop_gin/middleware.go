// Package dpop_gin provides Gin middleware with DPoP support
package dpop_gin

import (
	"errors"
	"net/http"
	"strings"

	"github.com/conductorone/dpop/pkg/dpop"
	"github.com/gin-gonic/gin"
)

// ErrMissingDPoPHeader is returned when the DPoP header is missing from the request
var ErrMissingDPoPHeader = errors.New("missing DPoP header")

// ErrInvalidAuthScheme is returned when the Authorization header has an invalid scheme
var ErrInvalidAuthScheme = errors.New("invalid authorization scheme")

const (
	// DPoPClaimsKey is the key used to store DPoP claims in the Gin context
	DPoPClaimsKey = "dpop-claims"
	// AuthorizationHeader is the standard HTTP header for authorization
	AuthorizationHeader = "Authorization"
	// DPoPScheme is the scheme used for DPoP bound tokens
	DPoPScheme = "DPoP"
	// BearerScheme is the scheme used for Bearer tokens
	BearerScheme = "Bearer"
)

// serverOptions configures the behavior of the DPoP middleware
type serverOptions struct {
	// validationOptions are the options for DPoP proof validation
	validationOptions []dpop.Option

	// nonceGenerator generates nonces for DPoP proofs
	nonceGenerator dpop.NonceGenerator

	// errorHandler handles errors during DPoP validation
	errorHandler func(*gin.Context, error)
}

// ServerOption configures how we set up the DPoP middleware
type ServerOption func(*serverOptions)

// WithValidationOptions sets the validation options for DPoP proof validation
func WithValidationOptions(opts ...dpop.Option) ServerOption {
	return func(o *serverOptions) {
		o.validationOptions = opts
	}
}

// WithNonceGenerator sets the nonce generator for DPoP proofs
func WithNonceGenerator(ng dpop.NonceGenerator) ServerOption {
	return func(o *serverOptions) {
		o.nonceGenerator = ng
	}
}

// WithErrorHandler sets the error handler function
func WithErrorHandler(h func(*gin.Context, error)) ServerOption {
	return func(o *serverOptions) {
		o.errorHandler = h
	}
}

// defaultServerOptions returns the default options for the middleware
func defaultServerOptions() *serverOptions {
	return &serverOptions{
		validationOptions: nil, // Will use defaults from dpop.NewValidator
		errorHandler:      defaultErrorHandler,
	}
}

// Middleware creates a new Gin middleware with DPoP support
func Middleware(opts ...ServerOption) gin.HandlerFunc {
	options := defaultServerOptions()
	for _, opt := range opts {
		opt(options)
	}

	validator := dpop.NewValidator(options.validationOptions...)

	return func(c *gin.Context) {
		// Skip validation for preflight requests
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}

		// Generate and set a new nonce for the next request if configured
		if options.nonceGenerator != nil {
			nonce, err := options.nonceGenerator(c.Request.Context())
			if err != nil {
				options.errorHandler(c, err)
				c.Abort()
				return
			}
			c.Header(dpop.NonceHeaderName, nonce)
		}

		// Get the DPoP proof and Authorization header
		dpopProof := c.GetHeader(dpop.HeaderName)
		authHeader := c.GetHeader(AuthorizationHeader)

		// Parse Authorization header if present
		var authScheme, accessToken string
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 {
				options.errorHandler(c, ErrInvalidAuthScheme)
				c.Abort()
				return
			}
			authScheme = parts[0]
			accessToken = parts[1]
		}

		// If there's no DPoP proof and no DPoP Authorization header, proceed with the request
		// This allows the middleware to be used in chains where some endpoints don't require DPoP
		if dpopProof == "" && authScheme != DPoPScheme {
			c.Next()
			return
		}

		// Here, we know this request must be DPoP validated, so make sure we have a proof.
		if dpopProof == "" {
			options.errorHandler(c, ErrMissingDPoPHeader)
			c.Abort()
			return
		}

		// If we have an Authorization header, it must be DPoP
		if len(authHeader) > 0 && authScheme != DPoPScheme {
			options.errorHandler(c, ErrInvalidAuthScheme)
			c.Abort()
			return
		}

		var validationOpts []dpop.ValidationProofOption
		if authScheme == DPoPScheme {
			// If using DPoP scheme, the proof MUST be bound to the access token
			validationOpts = append(validationOpts, dpop.WithProofExpectedAccessToken(accessToken))
		}

		claims, err := validator.ValidateProof(c.Request.Context(), dpopProof, c.Request.Method, getRequestURL(c.Request), validationOpts...)
		if err != nil {
			options.errorHandler(c, err)
			c.Abort()
			return
		}

		// Store the validated claims in the context
		c.Set(DPoPClaimsKey, claims)
		c.Next()
	}
}

// GetClaims retrieves DPoP claims from the Gin context
func GetClaims(c *gin.Context) (*dpop.Claims, bool) {
	claims, exists := c.Get(DPoPClaimsKey)
	if !exists {
		return nil, false
	}
	dpopClaims, ok := claims.(*dpop.Claims)
	return dpopClaims, ok
}

// defaultErrorHandler is the default error handler for DPoP validation errors
func defaultErrorHandler(c *gin.Context, err error) {
	switch {
	case err == ErrMissingDPoPHeader:
		c.JSON(http.StatusUnauthorized, gin.H{"error": "DPoP header required"})
	case err == ErrInvalidAuthScheme:
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization scheme"})
	case err == dpop.ErrInvalidProof:
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid DPoP proof"})
	case err == dpop.ErrExpiredProof:
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Expired DPoP proof"})
	case err == dpop.ErrInvalidNonce:
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid DPoP nonce"})
	case err == dpop.ErrInvalidTokenBinding:
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid DPoP token binding"})
	default:
		c.JSON(http.StatusUnauthorized, gin.H{"error": "DPoP validation failed"})
	}
}

// getRequestURL returns the full URL of the request
func getRequestURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.String()
}
