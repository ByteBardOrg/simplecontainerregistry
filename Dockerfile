# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.26

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath -ldflags="-s -w" -o /out/scr ./cmd/simplecontainerregistry

RUN mkdir -p /out/var/lib/scr/registry

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/scr /usr/local/bin/scr
COPY --chown=nonroot:nonroot config.container.yaml /etc/scr/config.yaml
COPY --from=build --chown=nonroot:nonroot /out/var/lib/scr /var/lib/scr

USER nonroot:nonroot
EXPOSE 5000
VOLUME ["/var/lib/scr"]

ENTRYPOINT ["/usr/local/bin/scr"]
CMD ["-config", "/etc/scr/config.yaml"]
