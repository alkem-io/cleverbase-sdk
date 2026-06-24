# Credential-free mock upstream (CSC/OIDC + RFC 3161 TSA). Needs openssl at runtime for the TSA and
# bakes the synthetic test fixtures at /fixtures. Build context MUST be the repository root:
#   docker build -f examples/reference-integration/mock-upstream/Dockerfile -t cleverbase-refmock .
# syntax=docker/dockerfile:1

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY examples/reference-integration/mock-upstream ./mock-upstream
WORKDIR /src/mock-upstream
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /mockupstream ./cmd/mockupstream

FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && useradd -u 65532 -r -s /usr/sbin/nologin nonroot
COPY --from=build /mockupstream /usr/local/bin/mockupstream
# The mock only needs the committed DER/PKCS#8 PKI + the upstream JSON shapes. Make them readable by
# the non-root runtime user. The keys under tests/fixtures/pki are SYNTHETIC TEST keys ONLY; this
# image is published to GHCR, so a real key must NEVER be placed under that path — it would be baked
# in world-readable.
COPY tests/fixtures/upstream /fixtures/upstream
COPY tests/fixtures/pki /fixtures/pki
RUN chmod -R a+rX /fixtures
USER 65532
ENV REFMOCK_FIXTURES_DIR=/fixtures REFMOCK_LISTEN=:9000 TMPDIR=/tmp
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/mockupstream"]
