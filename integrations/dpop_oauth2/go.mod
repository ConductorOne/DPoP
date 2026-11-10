module github.com/conductorone/dpop/integrations/dpop_oauth2

go 1.26.0

require (
	github.com/conductorone/dpop v0.3.0
	github.com/go-jose/go-jose/v4 v4.1.9
	github.com/google/uuid v1.6.0
	github.com/stretchr/testify v1.11.1
	golang.org/x/oauth2 v0.38.0
)

replace github.com/conductorone/dpop => ../..

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/jellydator/ttlcache/v3 v3.4.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
