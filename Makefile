GO ?= go

.PHONY: all test vet lint tidy check

all: check

test:
	$(GO) test -race -count=1 ./...

vet:
	$(GO) vet ./...

# golangci-lint v2 (see .golangci.yml).
lint:
	golangci-lint run ./...

tidy:
	$(GO) mod tidy

check: vet test
