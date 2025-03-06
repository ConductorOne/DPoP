module github.com/conductorone/dpop/integrations/dpop_grpc

go 1.23.4

require (
	github.com/conductorone/dpop v0.0.2
	github.com/go-jose/go-jose/v4 v4.0.4
	github.com/stretchr/testify v1.9.0
	golang.org/x/oauth2 v0.26.0
	google.golang.org/grpc v1.70.0
	google.golang.org/protobuf v1.36.5
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jellydator/ttlcache/v3 v3.3.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.34.0 // indirect
	golang.org/x/net v0.35.0 // indirect
	golang.org/x/sync v0.11.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250219182151-9fdb1cabc7b2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/conductorone/dpop => ../..
