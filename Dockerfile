# syntax=docker/dockerfile:1.7

# Two images from one file: build a target with
#   docker buildx build --target wg-hub   -t ghcr.io/teknoir/wg-hub   .
#   docker buildx build --target wg-agent -t ghcr.io/teknoir/wg-agent .
#
# The Go toolchain runs on the build host's architecture and cross-compiles
# (CGO off, so no C toolchain and no emulation is needed); the final stage only
# copies one static binary. Both base images are pinned by digest.

ARG GO_IMAGE=golang:1.26-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade
ARG BASE_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=dev
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
# GOARM comes from the platform variant (linux/arm/v7 -> 7).
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    set -eu; \
    export GOOS="${TARGETOS}" GOARCH="${TARGETARCH}"; \
    if [ "${TARGETARCH}" = "arm" ]; then export GOARM="${TARGETVARIANT#v}"; fi; \
    for cmd in wg-hub wg-agent; do \
      go build -trimpath \
        -ldflags "-s -w -X github.com/teknoir/wg-tunnel/pkg/version.Version=${VERSION}" \
        -o "/out/${cmd}" "./cmd/${cmd}"; \
    done

# wg-hub: unprivileged, no TUN device, no capabilities. Listens on UDP 51820
# (WireGuard), TCP 8080 (outside session API), TCP 8081 (internal API: service
# account delegation and direct sessions) and TCP 9090 (metrics). The same
# binary runs `wg-hub flags-watcher` (metrics and health on 9090).
FROM ${BASE_IMAGE} AS wg-hub
COPY --from=build /out/wg-hub /usr/local/bin/wg-hub
USER 65532:65532
EXPOSE 8080 8081 9090 51820/udp
ENTRYPOINT ["/usr/local/bin/wg-hub"]

# wg-agent: no shell. The pod's init container runs `wg-agent init` as uid 0
# (runAsUser: 0) to prepare the identity directory; the agent itself runs as
# the image user 65532.
FROM ${BASE_IMAGE} AS wg-agent
COPY --from=build /out/wg-agent /usr/local/bin/wg-agent
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/wg-agent"]
CMD ["run"]
