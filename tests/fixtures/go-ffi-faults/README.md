# Go binding ABI fault fixture

`cleverbase_ffi.c` is an external test double for the native SDK library. It exports the same five
C symbols as `cleverbase-ffi` and returns bounded malformed or incomplete responses selected by the
test harness's `CLEVERBASE_FFI_FAULT` environment variable. A separately built public Go consumer
uses it to cover fail-closed ABI and wire-contract behavior that the real Rust library cannot emit.

The fixture is never linked into the binding, production artifacts, or ordinary tests. It contains
no SDK hook, product flag, protocol implementation, credential, or network access.
