# Reference frontend: bundle the no-crypto TS (with the frontend helper) + a tiny Go BFF that serves
# the static files and injects the API key when proxying /api/* to the signing service.
# Build context MUST be the repository root:
#   docker build -f examples/reference-integration/web/Dockerfile -t cleverbase-refweb .
# syntax=docker/dockerfile:1

# --- Stage 1: build the helper + bundle the frontend ---
FROM node:22-bookworm AS web
WORKDIR /src
COPY frontend/helper-ts ./frontend/helper-ts
RUN cd frontend/helper-ts && npm install --no-audit --no-fund && npm run build
COPY examples/reference-integration/web ./examples/reference-integration/web
RUN cd examples/reference-integration/web && npm install --no-audit --no-fund && npm run build

# --- Stage 2: build the BFF static server ---
FROM golang:1.26-bookworm AS server
WORKDIR /src
COPY examples/reference-integration/web/go.mod ./go.mod
COPY examples/reference-integration/web/server ./server
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /refweb ./server

# --- Stage 3: minimal non-root static runtime ---
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=server /refweb /usr/local/bin/refweb
COPY --from=web /src/examples/reference-integration/web/public /web
ENV REFWEB_STATIC_DIR=/web REFWEB_LISTEN=:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/refweb"]
