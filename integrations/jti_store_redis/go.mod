module github.com/conductorone/dpop/integrations/jti_store_redis

go 1.23.6

require (
	github.com/alicebob/miniredis/v2 v2.34.0
	github.com/redis/go-redis/v9 v9.7.1
	github.com/stretchr/testify v1.9.0
)

require (
	github.com/alicebob/gopher-json v0.0.0-20230218143504-906a9b012302 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	go.uber.org/zap v1.27.0
)

replace github.com/conductorone/dpop => ../..
