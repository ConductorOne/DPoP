// Package dpop_http provides net/http server middleware with DPoP support
package dpop_http

import (
	"errors"
	"net/http"
	"strings"

	"github.com/conductorone/dpop/pkg/dpop"
)

var (
	// ErrMissingDPoPHeader is returned when the DPoP header is missing
	ErrMissingDPoPHeader = errors.New("missing DPoP header")

	// ErrInvalidDPoPHeader is returned when the DPoP header is invalid
	ErrInvalidDPoPHeader = errors.New("invalid DPoP header")

	// ErrInvalidAuthScheme is returned when the Authorization header has an invalid scheme
	ErrInvalidAuthScheme = errors.New("invalid authorization scheme")
)

const (
	// AuthorizationHeader is the standard HTTP header for authorization
	AuthorizationHeader = "Authorization"
	// DPoPScheme is the scheme used for DPoP bound tokens
	DPoPScheme = "DPoP"
	// BearerScheme is the scheme used for Bearer tokens
	BearerScheme = "Bearer"
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

			// Skip validation for preflight requests
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

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

			// Get the DPoP proof and Authorization header
			dpopProof := r.Header.Get(dpop.HeaderName)
			authHeader := r.Header.Get(AuthorizationHeader)

			// Parse Authorization header if present
			var authScheme, accessToken string
			if authHeader != "" {
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) != 2 {
					if options.errorHandler != nil {
						options.errorHandler(w, r, ErrInvalidAuthScheme)
					}
					return
				}
				authScheme = parts[0]
				accessToken = parts[1]
			}

			// If there's no DPoP proof and no DPoP Authorization header, proceed with the request
			// This allows the middleware to be used in chains where some endpoints don't require DPoP
			if dpopProof == "" && authScheme != DPoPScheme {
				next.ServeHTTP(w, r)
				return
			}

			// Here, we know this request must be DPoP validated, so make sure we have a proof.
			if dpopProof == "" {
				if options.errorHandler != nil {
					options.errorHandler(w, r, ErrMissingDPoPHeader)
				}
				return
			}

			// If we have an Authorization header, it must be DPoP
			if len(authHeader) > 0 && authScheme != DPoPScheme {
				if options.errorHandler != nil {
					options.errorHandler(w, r, ErrInvalidAuthScheme)
				}
				return
			}

			var validationOpts []dpop.ValidationProofOption
			if authScheme == DPoPScheme {
				// If using DPoP scheme, the proof MUST be bound to the access token
				validationOpts = append(validationOpts, dpop.WithProofExpectedAccessToken(accessToken))
			}

			// Validate the proof
			claims, err := validator.ValidateProof(ctx, dpopProof, r.Method, getRequestURL(r), validationOpts...)
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
	case errors.Is(err, ErrInvalidAuthScheme):
		http.Error(w, "Invalid authorization scheme", http.StatusUnauthorized)
	case errors.Is(err, dpop.ErrInvalidProof):
		http.Error(w, "Invalid DPoP proof", http.StatusUnauthorized)
	case errors.Is(err, dpop.ErrExpiredProof):
		http.Error(w, "Expired DPoP proof", http.StatusUnauthorized)
	case errors.Is(err, dpop.ErrInvalidNonce):
		http.Error(w, "Invalid DPoP nonce", http.StatusUnauthorized)
	case errors.Is(err, dpop.ErrInvalidTokenBinding):
		http.Error(w, "Invalid DPoP token binding", http.StatusUnauthorized)
	default:
		http.Error(w, "DPoP validation failed", http.StatusUnauthorized)
	}
}
