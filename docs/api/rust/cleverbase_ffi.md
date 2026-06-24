# Crate `cleverbase_ffi`

Stable C ABI over `cleverbase-core` (contracts/sdk-api.md).

Two functions, mirroring Cleverbase's own `scal3` boundary: a coarse CBOR-in / CBOR-out
`cleverbase_process`, and `cleverbase_free` to release the returned buffer. The CBOR envelope
is versioned (`schema_version`), so the ABI stays stable within a SemVer major.

## Functions

### fn `cleverbase_free`

```rust
unsafe extern "C" fn cleverbase_free(ptr: *mut u8, len: usize)
```

Free a buffer previously returned by [`cleverbase_process`].

# Safety
`ptr`/`len` must be exactly what a prior `cleverbase_process` call wrote, freed at most once.

### fn `cleverbase_process`

```rust
unsafe extern "C" fn cleverbase_process(in_ptr: *const u8, in_len: usize, out_ptr: *mut *mut u8, out_len: *mut usize) -> i32
```

Process one CBOR request envelope.

On success writes a heap buffer to `*out_ptr`/`*out_len` (free it with [`cleverbase_free`]) and
returns `0`. Returns non-zero for null arguments. Protocol/usage errors are returned *inside*
the CBOR response (a `WireResult::Err`), not via the status code.

# Safety
`in_ptr` must point to `in_len` readable bytes; `out_ptr`/`out_len` must be valid for writes.

### fn `process_bytes`

```rust
fn process_bytes(input: &[u8]) -> Vec<u8>
```

Decode → dispatch → encode. Pure; shared by the C ABI, language bindings, and tests
(single source of truth — Constitution Principle III).
