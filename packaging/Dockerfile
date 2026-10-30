# fleetreach container image, built by .github/workflows/release.yml from the release
# binaries (it does not compile anything). The workflow stages them as
# packaging/bin/<amd64|arm64>/fleetreach before building.
#
#   docker run --rm -v "$PWD:/work" ghcr.io/tess-fun/fleetreach scan -c fleet.toml
#
# Mount a volume on /cache to keep the OSV exports, source checkouts and NVD answers
# between runs.
FROM debian:bookworm-slim

# git: fleet sources clone with it. ca-certificates: HTTPS to osv.dev, GitHub, CISA, FIRST.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 10001 fleetreach \
 && mkdir -p /cache /work \
 && chown fleetreach:fleetreach /cache /work \
 && chmod 0700 /cache

ARG TARGETARCH
COPY bin/${TARGETARCH}/fleetreach /usr/local/bin/fleetreach

USER fleetreach
ENV XDG_CACHE_HOME=/cache
WORKDIR /work
VOLUME ["/cache"]
ENTRYPOINT ["fleetreach"]
CMD ["--help"]
