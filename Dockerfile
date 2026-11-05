# tinylinkd container image.
#
# The image contains only the statically linked musl binary. CI builds the
# binaries with cargo-zigbuild and places them at dist/<TARGETARCH>/tld before
# calling buildx, so a plain `docker build` expects the same layout locally:
#
#   dist/amd64/tld   (x86_64-unknown-linux-musl)
#   dist/arm64/tld   (aarch64-unknown-linux-musl)
#
# buildx sets TARGETARCH automatically for each platform in the build.
FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETARCH

COPY --chown=nonroot:nonroot dist/${TARGETARCH}/tld /usr/local/bin/tld

# Container defaults; TLD_BASE_URL is supplied by the operator.
ENV TLD_LISTEN_ADDR=0.0.0.0:8080 \
    TLD_DATA_DIR=/data

EXPOSE 8080
VOLUME ["/data"]

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/tld", "serve"]
