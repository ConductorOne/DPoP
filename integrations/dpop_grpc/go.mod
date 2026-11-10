module github.com/conductorone/dpop/integrations/dpop_grpc

go 1.26.0

require (
	github.com/conductorone/dpop v0.4.0
	// RELEASE NOTE: this module uses dpop_oauth2 APIs newer than v0.2.5
	// (IsTransient, ErrTokenRequestTransient). The replace directive below
	// covers local builds only — consumers ignore it. When tagging a release
	// (make tag tags every module together), bump this require to that same
	// new tag or published dpop_grpc will not compile.
	github.com/conductorone/dpop/integrations/dpop_oauth2 v0.4.0
	github.com/go-jose/go-jose/v4 v4.1.9
	github.com/stretchr/testify v1.11.1
	golang.org/x/oauth2 v0.38.0
	google.golang.org/grpc v1.85.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jellydator/ttlcache/v3 v3.4.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261110000943-09e21b237f2c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/conductorone/dpop => ../..

replace github.com/conductorone/dpop/integrations/dpop_oauth2 => ../dpop_oauth2
