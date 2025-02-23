// Package dpop_http provides net/http server middleware with DPoP support
package dpop_http

import (
	"errors"
	"net/http"

	"github.com/conductorone/dpop/pkg/dpop"
)

var (
	// ErrMissingDPoPHeader is returned when the DPoP header is missing
	ErrMissingDPoPHeader = errors.New("missing DPoP header")

	// ErrInvalidDPoPHeader is returned when the DPoP header is invalid
	ErrInvalidDPoPHeader = errors.New("invalid DPoP header")
)

// serverOptions configures the behavior of the DPoP middleware
type serverOptions struct {
	// ValidationOptions are the options for DPoP proof validation
	validationOptions []dpop.Option

	// NonceGenerator generates nonces for DPoP proofs
	nonceGenerator dpop.NonceGenerator

	// ErrorHandler handles errors during DPoP validation
	errorHandler func(w http.ResponseWriter, r *http.Request, err error)
}

// ServerOption configures how we set up the DPoP middleware
type ServerOption func(*serverOptions)

// WithValidationOptions sets the validation options for DPoP proof validation
func WithValidationOptions(opts ...dpop.Option) ServerOption {
	return func(o *serverOptions) {
		o.validationOptions = opts
	}
}

// WithNonceGenerator sets the nonce generator function
func WithNonceGenerator(ng dpop.NonceGenerator) ServerOption {
	return func(o *serverOptions) {
		o.nonceGenerator = ng
	}
}

// WithErrorHandler sets the error handler function
func WithErrorHandler(h func(w http.ResponseWriter, r *http.Request, err error)) ServerOption {
	return func(o *serverOptions) {
		o.errorHandler = h
	}
}

// defaultServerOptions returns the default options for the middleware
func defaultServerOptions() *serverOptions {
	return &serverOptions{
		validationOptions: nil,
		errorHandler:      defaultErrorHandler,
	}
}

// Middleware creates a new DPoP middleware handler
func Middleware(opts ...ServerOption) func(http.Handler) http.Handler {
	options := defaultServerOptions()
	for _, opt := range opts {
		opt(options)
	}

	validator := dpop.NewValidator(options.validationOptions...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			// Generate and set a new nonce for the next request
			if options.nonceGenerator != nil {
				nonce, err := options.nonceGenerator(ctx)
				if err != nil {
					if options.errorHandler != nil {
						options.errorHandler(w, r, err)
					}
					return
				}
				w.Header().Set(dpop.NonceHeaderName, nonce)
			}

			// Get the DPoP proof from the header
			dpopProof := r.Header.Get(dpop.HeaderName)
			if dpopProof == "" {
				if options.errorHandler != nil {
					options.errorHandler(w, r, ErrMissingDPoPHeader)
				}
				return
			}

			// Validate the proof
			claims, err := validator.ValidateProof(ctx, dpopProof, r.Method, getRequestURL(r))
			if err != nil {
				if options.errorHandler != nil {
					options.errorHandler(w, r, err)
				}
				return
			}

			// Store the validated claims in the request context
			ctx = dpop.WithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
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

// defaultErrorHandler is the default error handler for DPoP validation errors
func defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrMissingDPoPHeader):
		http.Error(w, "DPoP header required", http.StatusUnauthorized)
	case errors.Is(err, dpop.ErrInvalidProof):
		http.Error(w, "Invalid DPoP proof", http.StatusUnauthorized)
	case errors.Is(err, dpop.ErrExpiredProof):
		http.Error(w, "Expired DPoP proof", http.StatusUnauthorized)
	case errors.Is(err, dpop.ErrInvalidNonce):
		http.Error(w, "Invalid DPoP nonce", http.StatusUnauthorized)
	default:
		http.Error(w, "DPoP validation failed", http.StatusUnauthorized)
	}
}
