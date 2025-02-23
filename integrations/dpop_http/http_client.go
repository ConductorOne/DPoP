// Package dpop_http provides a net/http client with DPoP support
package dpop_http

import (
	"crypto"
	"net/http"

	"github.com/conductorone/dpop/pkg/dpop"
	"golang.org/x/oauth2"
)

// Transport implements http.RoundTripper and adds DPoP proof headers to requests.
// It can be composed with other RoundTrippers like oauth2.Transport.
type Transport struct {
	// Base is the base RoundTripper used to make HTTP requests.
	// If nil, http.DefaultTransport is used.
	Base http.RoundTripper

	// TokenSource provides the access token for requests.
	TokenSource oauth2.TokenSource

	// Proofer generates DPoP proofs for requests
	proofer *dpop.Proofer

	// ProofOptions are additional options for DPoP proof generation
	ProofOptions []dpop.ProofOption
}

// RoundTrip implements http.RoundTripper
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Get the token from the source
	token, err := t.TokenSource.Token()
	if err != nil {
		return nil, err
	}

	// Set the Authorization header
	req.Header.Set("Authorization", token.TokenType+" "+token.AccessToken)

	// Generate DPoP proof with the access token
	proofOpts := append([]dpop.ProofOption{}, t.ProofOptions...)
	proofOpts = append(proofOpts, dpop.WithAccessToken(token.AccessToken))

	// Generate and set the DPoP header
	dpopProof, err := t.proofer.CreateProof(req.Context(), req.Method, req.URL.String(), proofOpts...)
	if err != nil {
		return nil, err
	}
	req.Header.Set(dpop.HeaderName, dpopProof)

	return t.base().RoundTrip(req)
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

// NewTransport creates a new Transport with the given key and token getter
func NewTransport(base http.RoundTripper, key crypto.PrivateKey, tokenSource oauth2.TokenSource, opts ...dpop.ProofOption) (*Transport, error) {
	proofer, err := dpop.NewProofer(key)
	if err != nil {
		return nil, err
	}

	return &Transport{
		Base:         base,
		TokenSource:  tokenSource,
		proofer:      proofer,
		ProofOptions: opts,
	}, nil
}
