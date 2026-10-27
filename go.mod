module github.com/digitooai/onetime

go 1.25.0

// Pinned to a patched release. The `go` directive above is the language
// version and stays conservative, but it is also what CI feeds to setup-go —
// and building with 1.25.0 pulled in 32 known standard-library
// vulnerabilities that govulncheck rightly refused to pass. The runtime image
// already used a patched toolchain; this makes CI agree.
toolchain go1.25.14

require (
	github.com/alicebob/miniredis/v2 v2.38.0
	github.com/prometheus/client_golang v1.24.1
	github.com/redis/go-redis/v9 v9.22.0
	golang.org/x/crypto v0.55.0
	golang.org/x/text v0.41.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.70.1 // indirect
	github.com/prometheus/procfs v0.21.1 // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
