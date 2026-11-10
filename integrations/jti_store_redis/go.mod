module github.com/conductorone/dpop/integrations/jti_store_redis

go 1.26.0

require (
	github.com/alicebob/miniredis/v2 v2.34.0
	github.com/redis/go-redis/v9 v9.23.0
	github.com/stretchr/testify v1.12.1
)

require (
	github.com/alicebob/gopher-json v0.0.0-20230218143504-906a9b012302 // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	go.uber.org/atomic v1.12.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sys v0.50.0 // indirect
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	go.uber.org/zap v1.28.0
)

replace github.com/conductorone/dpop => ../..
