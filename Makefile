GO ?= go

.PHONY: all test vet lint tidy check docker-hub docker-agent docker

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

# Container images (see Dockerfile). Override REGISTRY, VERSION, PLATFORMS or
# DOCKER_FLAGS, e.g. `make docker-agent PLATFORMS=linux/amd64,linux/arm64,linux/arm/v7 DOCKER_FLAGS=--push`.
REGISTRY ?= ghcr.io/teknoir
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PLATFORMS ?= linux/amd64
DOCKER_FLAGS ?= --load

docker: docker-hub docker-agent

docker-hub:
	docker buildx build --target wg-hub --platform $(PLATFORMS) --build-arg VERSION=$(VERSION) \
		-t $(REGISTRY)/wg-hub:$(VERSION) $(DOCKER_FLAGS) .

docker-agent:
	docker buildx build --target wg-agent --platform $(PLATFORMS) --build-arg VERSION=$(VERSION) \
		-t $(REGISTRY)/wg-agent:$(VERSION) $(DOCKER_FLAGS) .
