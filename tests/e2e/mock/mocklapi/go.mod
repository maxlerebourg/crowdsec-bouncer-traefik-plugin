// Standalone module so this test helper stays out of the plugin module:
// it is excluded from the plugin's `go build ./...`, `go test ./...`,
// golangci-lint and `go mod vendor`. Stdlib only — no dependencies.
module mocklapi

go 1.22
