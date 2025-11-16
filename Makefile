.PHONY: test
test:
	go test -v ./cmd/veilwarden

.PHONY: test-integration
test-integration:
	go test -v -tags=integration ./cmd/veilwarden

.PHONY: test-all
test-all: test test-integration
