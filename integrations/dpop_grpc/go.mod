module github.com/conductorone/dpop/integrations/dpop_grpc

go 1.23.6

require (
	github.com/conductorone/dpop v0.0.0-00010101000000-000000000000
	github.com/go-jose/go-jose/v4 v4.0.4
	github.com/stretchr/testify v1.9.0
	golang.org/x/oauth2 v0.26.0
	google.golang.org/grpc v1.70.0
	google.golang.org/protobuf v1.35.2
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jellydator/ttlcache/v3 v3.3.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.30.0 // indirect
	golang.org/x/net v0.32.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241202173237-19429a94021a // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/conductorone/dpop => ../..
