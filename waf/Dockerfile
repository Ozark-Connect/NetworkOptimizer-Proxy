# Builds on the runner's platform and cross-compiles, so a multi-arch image needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go VERSION ./
COPY apps ./apps
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /netopt-waf .
# A named volume takes this directory's owner on first use, so nonroot can write its state.
RUN mkdir -p /state

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /netopt-waf /netopt-waf
COPY --from=build --chown=65532:65532 /state /var/lib/netopt-waf
USER nonroot
ENTRYPOINT ["/netopt-waf"]
