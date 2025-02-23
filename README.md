# DPoP (Demonstrating Proof of Possession)

This is a Go implementation of the [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449) specification.

## Core Features

- RFC 9449 compliant DPoP proof generation and validation
- JTI-based replay attack prevention with configurable time windows
- Built-in integrations:
  - `net/http` client and server middleware
  - gRPC interceptors
  - Gin framework middleware
  - Redis-backed JTI-replay prevention storage
- Ed25519 and RSA signing key support
- Context propagation throughout the API
- No external dependencies in core package
- Comprehensive test coverage

## Project Structure

### Core Package

- `pkg/dpop` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/dpop/pkg/dpop.svg)](https://pkg.go.dev/github.com/conductorone/dpop/pkg/dpop)
  - Core DPoP implementation including proof generation and validation
  - Implements the core RFC 9449 functionality

### Framework Integrations

- `integrations/dpop_http` - Standard `net/http` client and server implementations
- `integrations/dpop_grpc` - gRPC client and server interceptors
- `integrations/dpop_gin` - Gin framework middleware
- `integrations/jti_store_redis` - Redis-based proof storage and validation

## Usage Examples

### Basic DPoP Proof Generation

```go
import (
    "crypto/ed25519"
    "github.com/conductorone/dpop/pkg/dpop"
)

// Generate or load your private key
_, privateKey, _ := ed25519.GenerateKey(nil)

// Create a new proofer
proofer, err := dpop.NewProofer(privateKey)
if err != nil {
    // Handle error
}

// Generate a DPoP proof
proof, err := proofer.CreateProof(ctx, "POST", "https://api.example.com/token")
```

### HTTP Client Integration

```go
import (
    "crypto/ed25519"
    "github.com/conductorone/dpop/integrations/dpop_http"
)

// Generate or load your private key
_, privateKey, _ := ed25519.GenerateKey(nil)

// Create a DPoP-enabled HTTP transport
transport, err := dpop_http.NewTransport(
    http.DefaultTransport,
    privateKey,
    tokenSource, // your oauth2.TokenSource
)
if err != nil {
    // Handle error
}

// Create a client with the transport
client := &http.Client{Transport: transport}

// DPoP proofs are automatically attached to requests
resp, err := client.Get("https://api.example.com/resource")
```

### gRPC Integration

```go
import (
    "crypto/ed25519"
    "github.com/conductorone/dpop/integrations/dpop_grpc"
)

// Generate or load your private key
_, privateKey, _ := ed25519.GenerateKey(nil)

// Create and use a DPoP interceptor
interceptor, err := dpop_grpc.NewClientInterceptor(privateKey)
if err != nil {
    // Handle error
}

conn, err := grpc.Dial(
    address,
    grpc.WithUnaryInterceptor(interceptor.UnaryClientInterceptor()),
)
```

## Security

If you discover a security issue, please report it by sending an email to [security@conductorone.com](mailto:security@conductorone.com). Please do not file a public issue or pull request.

We appreciate your help in making this project more secure and will acknowledge your contributions.

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](./LICENSE) file for details. 