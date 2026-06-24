# Reference signing service: Rust staticlib → cgo build → distroless/cc.
# Build context MUST be the repository root:
#   docker build -f examples/reference-integration/signing-service/Dockerfile -t cleverbase-refsvc .
# syntax=docker/dockerfile:1

# --- Stage 1: build the cleverbase-ffi staticlib ---
FROM rust:1.94-bookworm AS rust
WORKDIR /src
# rust-toolchain.toml is intentionally NOT copied: the base image pins the toolchain and the
# pinned components (clippy/llvm-tools) are not needed for `cargo build`.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --locked --release -p cleverbase-ffi

# --- Stage 2: build the Go service, statically linking the staticlib ---
FROM golang:1.26-bookworm AS go
WORKDIR /src
COPY --from=rust /src/target/release/libcleverbase_ffi.a /libs/libcleverbase_ffi.a
COPY bindings ./bindings
COPY examples/reference-integration/signing-service ./examples/reference-integration/signing-service
# mock-upstream is referenced only by the e2e test (a replace target); copy it so the module graph
# resolves, even though `go build ./cmd/refsvc` does not link it.
COPY examples/reference-integration/mock-upstream ./examples/reference-integration/mock-upstream
WORKDIR /src/examples/reference-integration/signing-service
ENV CGO_ENABLED=1
# Override the binding's default -L (which points at target/debug) to the staticlib we just built.
# With only the .a present (no .so), the linker links cleverbase-ffi statically.
ENV CGO_LDFLAGS="-L/libs"
RUN go build -trimpath -ldflags="-s -w" -o /refsvc ./cmd/refsvc

# --- Stage 3: minimal non-root runtime (glibc for cgo) ---
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=go /refsvc /usr/local/bin/refsvc
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/refsvc"]
