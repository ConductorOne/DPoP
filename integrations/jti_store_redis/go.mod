module github.com/conductorone/dpop/integrations/jti_store_redis

go 1.23.6

require github.com/redis/go-redis/v9 v9.7.1

require (
	github.com/stretchr/testify v1.9.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	go.uber.org/zap v1.27.0
)

replace github.com/conductorone/dpop => ../..
