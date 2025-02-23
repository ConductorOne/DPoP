// Package dpop_gin provides Gin middleware with DPoP support
package dpop_gin

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/dpop-new/pkg/dpop"
)

// ErrMissingDPoPHeader is returned when the DPoP header is missing from the request
var ErrMissingDPoPHeader = errors.New("missing DPoP header")

const (
	// DPoPClaimsKey is the key used to store DPoP claims in the Gin context
	DPoPClaimsKey = "dpop-claims"
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

		// Get the DPoP proof from the header
		dpopProof := c.GetHeader(dpop.HeaderName)
		if dpopProof == "" {
			options.errorHandler(c, ErrMissingDPoPHeader)
			c.Abort()
			return
		}

		// Validate the proof
		claims, err := validator.ValidateProof(c.Request.Context(), dpopProof, c.Request.Method, getRequestURL(c.Request))
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
	case err == dpop.ErrInvalidProof:
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid DPoP proof"})
	case err == dpop.ErrExpiredProof:
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Expired DPoP proof"})
	case err == dpop.ErrInvalidNonce:
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid DPoP nonce"})
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
