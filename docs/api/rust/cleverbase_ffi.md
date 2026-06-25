# Crate `cleverbase_ffi`

Stable C ABI over `cleverbase-core` + `cleverbase-attestation` (contracts/sdk-api.md,
contracts/verifier.md).

Signing mirrors Cleverbase's own `scal3` boundary: a coarse CBOR-in / CBOR-out
`cleverbase_process`, and `cleverbase_free` to release the returned buffer. The EUDI attestation
domain adds `cleverbase_attestation_verify` over the same CBOR-in / CBOR-out + `cleverbase_free`
pattern (the always-on verifier bar). Each CBOR envelope is versioned (`schema_version`), so the
ABI stays stable within a SemVer major.

`cleverbase_attestation_verify` is the **attestation verifier seam**: it runs the always-on bar
(contracts/verifier.md) over the CBOR `VerifyRequest` envelope and returns the
`cleverbase_attestation::wire::VerifyOutcome` (the verdict, or a decode error) inside the CBOR
response (status `0`). All protocol logic lives in the core crates; this layer only does the
pointer/length/free dance (Principle III).

## Functions

### fn `cleverbase_attestation_issuance`

```rust
unsafe extern "C" fn cleverbase_attestation_issuance(in_ptr: *const u8, in_len: usize, out_ptr: *mut *mut u8, out_len: *mut usize) -> i32
```

Drive one issuance operation (the gated OpenID4VCI `obtain` / OpenID4VP holder `present` flow —
contracts/holder-signer-hook.md, US2).

CBOR-in / CBOR-out, identical envelope discipline to [`cleverbase_attestation_verify`]: on success
writes a heap buffer to `*out_ptr`/`*out_len` (free it with [`cleverbase_free`]) and returns `0`;
returns non-zero only for null arguments (`1`) or a contained panic (`2`). The issuance *outcome*
(the next sans-IO host effect — an HTTP request or a holder **sign** — the opaque session/prepared
handle, or a decode error) is carried *inside* the CBOR response (a
`cleverbase_attestation::issuance::wire::IssuanceOutcome`), never via the status code.

The holder private key never crosses this boundary: a `Sign` effect surfaces the SDK-built signing
input for the host's HSM/KMS to sign out-of-process (FR-009); the host feeds the signature back via
a resume operation. When no issuer API is configured (`kind = None`) the flow is **skipped** (a
clear skipped outcome, never a failure — FR-008). This is an **additive** surface (its own schema
version); the verifier surface above is unchanged.

# Safety
`in_ptr` must point to `in_len` readable bytes; `out_ptr`/`out_len` must be valid for writes.

### fn `cleverbase_attestation_verify`

```rust
unsafe extern "C" fn cleverbase_attestation_verify(in_ptr: *const u8, in_len: usize, out_ptr: *mut *mut u8, out_len: *mut usize) -> i32
```

Verify a presented EUDI attestation (the always-on bar — contracts/verifier.md).

CBOR-in / CBOR-out, identical envelope discipline to [`cleverbase_process`]: on success writes a
heap buffer to `*out_ptr`/`*out_len` (free it with [`cleverbase_free`]) and returns `0`; returns
non-zero only for null arguments (`1`) or a contained panic (`2`). The verification *outcome*
(the verdict, or any decode error) is carried *inside* the CBOR response (a
`cleverbase_attestation::wire::VerifyOutcome`), never via the status code.

A well-formed request runs the always-on verifier bar and returns `VerifyOutcome::Ok { result }`;
a malformed/unsupported-version one returns `VerifyOutcome::Err` — both with status `0`.

# Safety
`in_ptr` must point to `in_len` readable bytes; `out_ptr`/`out_len` must be valid for writes.

### fn `cleverbase_free`

```rust
unsafe extern "C" fn cleverbase_free(ptr: *mut u8, len: usize)
```

Free a buffer previously returned by [`cleverbase_process`], [`cleverbase_attestation_verify`], or
[`cleverbase_attestation_issuance`] (all hand back an identically shaped boxed slice).

# Safety
`ptr`/`len` must be exactly what a prior `cleverbase_process` / `cleverbase_attestation_verify` /
`cleverbase_attestation_issuance` call wrote, freed at most once.

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
