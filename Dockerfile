## Build stage
# Runs on the build host's native platform and cross-compiles for the target
# via GOOS/GOARCH, so multi-arch builds don't need slow QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/frp-ip-filter .

# scratch has no chown, so pre-create the data dir owned by the fixed
# non-root UID/GID below, then copy it into the final image.
RUN mkdir /data && chown 10001:10001 /data

## Runtime stage
FROM scratch

COPY --from=build /out/frp-ip-filter /app/frp-ip-filter
COPY --from=build --chown=10001:10001 /data /data

WORKDIR /app

# Kept separate from /app: a volume mounted over /app would shadow the
# binary (bind mounts always, named volumes on any rebuild after the first).
ENV ALLOWLIST_PATH=/data/allowlist.json
VOLUME ["/data"]

# Numeric UID: no /etc/passwd in scratch, and the app never resolves it to a
# name. Override with --user/compose `user:` if you need a different one —
# just make sure it matches whatever owns the mounted volume.
USER 10001:10001

EXPOSE 8080 9090

ENTRYPOINT ["./frp-ip-filter"]
