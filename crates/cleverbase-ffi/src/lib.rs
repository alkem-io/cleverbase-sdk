//! Stable C ABI over `cleverbase-core` + `cleverbase-attestation` (contracts/sdk-api.md,
//! contracts/verifier.md).
//!
//! Signing mirrors Cleverbase's own `scal3` boundary: a coarse CBOR-in / CBOR-out
//! `cleverbase_process`, and `cleverbase_free` to release the returned buffer. The EUDI attestation
//! domain adds `cleverbase_attestation_verify` over the same CBOR-in / CBOR-out + `cleverbase_free`
//! pattern (the always-on verifier bar). Each CBOR envelope is versioned (`schema_version`), so the
//! ABI stays stable within a SemVer major.
//!
//! `cleverbase_attestation_verify` is the **attestation verifier seam**: it runs the always-on bar
//! (contracts/verifier.md) over the CBOR `VerifyRequest` envelope and returns the
//! `cleverbase_attestation::wire::VerifyOutcome` (the verdict, or a decode error) inside the CBOR
//! response (status `0`). All protocol logic lives in the core crates; this layer only does the
//! pointer/length/free dance (Principle III).

// The workspace pins a strict `restriction` lint set (unwrap/expect/panic/indexing/…) for library
// code. The `#[cfg(test)]` module below uses those constructs as test assertions, where a panic IS
// the intended failure signal, so re-allow them under `cfg(test)` only.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use cleverbase_core::wire::{decode_request, encode_response, WireOp, WireRequest, WireResult};

/// Pure dispatch from a decoded request to a result — the only logic here; everything else is the
/// core (Constitution Principle III: no protocol logic duplicated in bindings).
fn dispatch(req: WireRequest) -> WireResult {
    match req.op {
        WireOp::Begin {
            request,
            config,
            ctx,
        } => match cleverbase_core::begin(request, config, ctx) {
            Ok((handle, step)) => WireResult::Ok { handle, step },
            Err(e) => WireResult::Err {
                message: e.to_string(),
            },
        },
        WireOp::Resume { handle, input, ctx } => {
            match cleverbase_core::resume(handle, input, ctx) {
                Ok((handle, step)) => WireResult::Ok { handle, step },
                Err(e) => WireResult::Err {
                    message: e.to_string(),
                },
            }
        }
    }
}

/// Decode → dispatch → encode. Pure; shared by the C ABI, language bindings, and tests
/// (single source of truth — Constitution Principle III).
pub fn process_bytes(input: &[u8]) -> Vec<u8> {
    let result = match decode_request(input) {
        Ok(req) => dispatch(req),
        Err(message) => WireResult::Err { message },
    };
    encode_response(result)
}

/// The shared C-ABI pointer/null/`catch_unwind`/hand-off dance for a CBOR-in / CBOR-out function
/// (single source of truth for all `cleverbase_*` entry points — Constitution Principle III).
///
/// Reads `in_len` bytes from `in_ptr`, runs `process` (a pure CBOR-in / CBOR-out core function)
/// inside a `catch_unwind`, and hands the result to the caller as an exact-capacity boxed slice via
/// `*out_ptr`/`*out_len` (freed by [`cleverbase_free`]). Returns `0` on success, `1` for a null
/// argument, `2` for a contained panic — the identical status contract every entry point documents.
/// Protocol/usage errors are carried *inside* the returned CBOR (never via the status code).
///
/// # Safety
/// `in_ptr` must point to `in_len` readable bytes; `out_ptr`/`out_len` must be valid for writes.
unsafe fn run_cbor_abi(
    in_ptr: *const u8,
    in_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
    process: impl FnOnce(&[u8]) -> Vec<u8>,
) -> i32 {
    unsafe {
        if out_ptr.is_null() || out_len.is_null() {
            return 1;
        }
        // Initialize the outputs FIRST so every non-zero return below (null input or the panic path)
        // leaves a null/empty buffer for a consumer that inspects them, never uninitialized memory.
        *out_ptr = std::ptr::null_mut();
        *out_len = 0;
        if in_ptr.is_null() {
            return 1;
        }
        let input = std::slice::from_raw_parts(in_ptr, in_len);
        // A panic unwinding across the C ABI is undefined behavior; contain it and report status 2.
        // `process` borrows nothing observable across the boundary, so asserting unwind-safety is
        // sound (the only state is the local input slice + the returned Vec).
        let bytes = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| process(input)))
        {
            Ok(bytes) => bytes,
            Err(_) => return 2,
        };

        // Hand ownership to the caller as an exact-capacity boxed slice (cap == len), freed by
        // [`cleverbase_free`].
        let boxed = bytes.into_boxed_slice();
        let len = boxed.len();
        let ptr = Box::into_raw(boxed).cast::<u8>();
        *out_ptr = ptr;
        *out_len = len;
        0
    }
}

/// Process one CBOR request envelope.
///
/// On success writes a heap buffer to `*out_ptr`/`*out_len` (free it with [`cleverbase_free`]) and
/// returns `0`. Returns non-zero for null arguments. Protocol/usage errors are returned *inside*
/// the CBOR response (a `WireResult::Err`), not via the status code.
///
/// # Safety
/// `in_ptr` must point to `in_len` readable bytes; `out_ptr`/`out_len` must be valid for writes.
#[no_mangle]
pub unsafe extern "C" fn cleverbase_process(
    in_ptr: *const u8,
    in_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    // The pointer/null/catch_unwind/free dance is the shared `run_cbor_abi`; this entry only names the
    // signing-core `process_bytes` as the CBOR-in / CBOR-out body (DRY — Principle III).
    unsafe { run_cbor_abi(in_ptr, in_len, out_ptr, out_len, process_bytes) }
}

/// Verify a presented EUDI attestation (the always-on bar — contracts/verifier.md).
///
/// CBOR-in / CBOR-out, identical envelope discipline to [`cleverbase_process`]: on success writes a
/// heap buffer to `*out_ptr`/`*out_len` (free it with [`cleverbase_free`]) and returns `0`; returns
/// non-zero only for null arguments (`1`) or a contained panic (`2`). The verification *outcome*
/// (the verdict, or any decode error) is carried *inside* the CBOR response (a
/// `cleverbase_attestation::wire::VerifyOutcome`), never via the status code.
///
/// A well-formed request runs the always-on verifier bar and returns `VerifyOutcome::Ok { result }`;
/// a malformed/unsupported-version one returns `VerifyOutcome::Err` — both with status `0`.
///
/// # Safety
/// `in_ptr` must point to `in_len` readable bytes; `out_ptr`/`out_len` must be valid for writes.
#[no_mangle]
pub unsafe extern "C" fn cleverbase_attestation_verify(
    in_ptr: *const u8,
    in_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    // The pointer/null/catch_unwind/free dance is the shared `run_cbor_abi`; this entry only names the
    // attestation verifier core as the CBOR-in / CBOR-out body (DRY — Principle III).
    unsafe {
        run_cbor_abi(
            in_ptr,
            in_len,
            out_ptr,
            out_len,
            cleverbase_attestation::wire::process_verify_bytes,
        )
    }
}

/// Verify a **set-level** OpenID4VP `vp_token` (the multi-credential `{credential_id: [presentations]}`
/// map — contracts/openid4vp-verifier.md).
///
/// CBOR-in / CBOR-out, identical envelope discipline to [`cleverbase_attestation_verify`]: on success
/// writes a heap buffer to `*out_ptr`/`*out_len` (free it with [`cleverbase_free`]) and returns `0`;
/// returns non-zero only for null arguments (`1`) or a contained panic (`2`). The set-level outcome (the
/// overall `satisfied` verdict + per-credential results, or any decode error) is carried *inside* the
/// CBOR response (a `cleverbase_attestation::wire::WireVpTokenResponse`), never via the status code.
///
/// This is the only surface that folds the OpenID4VP **set-level** DCQL semantics (`credential_sets`
/// required option-sets + `multiple` cardinality) AND authenticates supplied signed Token Status List
/// tokens in-core across the whole `vp_token`; the single-presentation [`cleverbase_attestation_verify`]
/// enforces only the per-presentation single-query match. All protocol logic lives in the core; this
/// layer only does the pointer/length/free dance (Principle III).
///
/// # Safety
/// `in_ptr` must point to `in_len` readable bytes; `out_ptr`/`out_len` must be valid for writes.
#[no_mangle]
pub unsafe extern "C" fn cleverbase_attestation_verify_vp_token(
    in_ptr: *const u8,
    in_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    // The pointer/null/catch_unwind/free dance is the shared `run_cbor_abi`; this entry only names the
    // attestation set-level verifier core as the CBOR-in / CBOR-out body (DRY — Principle III).
    unsafe {
        run_cbor_abi(
            in_ptr,
            in_len,
            out_ptr,
            out_len,
            cleverbase_attestation::wire::process_vp_token_bytes,
        )
    }
}

/// Drive one issuance operation (the gated OpenID4VCI `obtain` / OpenID4VP holder `present` flow —
/// contracts/holder-signer-hook.md, US2).
///
/// CBOR-in / CBOR-out, identical envelope discipline to [`cleverbase_attestation_verify`]: on success
/// writes a heap buffer to `*out_ptr`/`*out_len` (free it with [`cleverbase_free`]) and returns `0`;
/// returns non-zero only for null arguments (`1`) or a contained panic (`2`). The issuance *outcome*
/// (the next sans-IO host effect — an HTTP request or a holder **sign** — the opaque session/prepared
/// handle, or a decode error) is carried *inside* the CBOR response (a
/// `cleverbase_attestation::issuance::wire::IssuanceOutcome`), never via the status code.
///
/// The holder private key never crosses this boundary: a `Sign` effect surfaces the SDK-built signing
/// input for the host's HSM/KMS to sign out-of-process (FR-009); the host feeds the signature back via
/// a resume operation. When no issuer API is configured (`kind = None`) the flow is **skipped** (a
/// clear skipped outcome, never a failure — FR-008). This is an **additive** surface (its own schema
/// version); the verifier surface above is unchanged.
///
/// # Safety
/// `in_ptr` must point to `in_len` readable bytes; `out_ptr`/`out_len` must be valid for writes.
#[no_mangle]
pub unsafe extern "C" fn cleverbase_attestation_issuance(
    in_ptr: *const u8,
    in_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    // The pointer/null/catch_unwind/free dance is the shared `run_cbor_abi`; this entry only names the
    // attestation issuance core as the CBOR-in / CBOR-out body (DRY — Principle III).
    unsafe {
        run_cbor_abi(
            in_ptr,
            in_len,
            out_ptr,
            out_len,
            cleverbase_attestation::issuance::wire::process_issuance_bytes,
        )
    }
}

/// Free a buffer previously returned by [`cleverbase_process`], [`cleverbase_attestation_verify`],
/// [`cleverbase_attestation_verify_vp_token`], or [`cleverbase_attestation_issuance`] (all hand back an
/// identically shaped boxed slice).
///
/// # Safety
/// `ptr`/`len` must be exactly what a prior `cleverbase_process` / `cleverbase_attestation_verify` /
/// `cleverbase_attestation_verify_vp_token` / `cleverbase_attestation_issuance` call wrote, freed at
/// most once.
#[no_mangle]
pub unsafe extern "C" fn cleverbase_free(ptr: *mut u8, len: usize) {
    unsafe {
        if ptr.is_null() {
            return;
        }
        let slice = std::slice::from_raw_parts_mut(ptr, len);
        drop(Box::from_raw(std::ptr::from_mut::<[u8]>(slice)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cleverbase_core::wire::{WireRequest, WireResponse, WireResult};
    use cleverbase_core::{
        ConformanceLevel, CscApi, Environment, HostContext, ResumeInput, Secret, SigningRequest,
        Step, TrustServiceConfiguration, SCHEMA_VERSION,
    };

    fn encode(req: &WireRequest) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(req, &mut buf).unwrap();
        buf
    }

    fn begin_envelope() -> Vec<u8> {
        let req = WireRequest {
            schema_version: SCHEMA_VERSION,
            op: WireOp::Begin {
                request: SigningRequest {
                    document: b"%PDF-1.7\nhi".to_vec(),
                    conformance_level: ConformanceLevel::BB,
                    expected_signer: None,
                    appearance: None,
                    signature_meta: None,
                },
                config: TrustServiceConfiguration {
                    environment: Environment::Acceptance,
                    csc_api: CscApi::V1Rsa,
                    client_id: "client-123".into(),
                    client_secret: Secret::new("shh"),
                    redirect_uri: "https://app.example/cb".into(),
                    tsa: None,
                },
                ctx: HostContext {
                    now_unix: 1_700_000_000,
                    entropy: vec![7u8; 16],
                },
            },
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&req, &mut buf).unwrap();
        buf
    }

    #[test]
    fn process_bytes_begin_returns_redirect() {
        let out = process_bytes(&begin_envelope());
        let resp: WireResponse = ciborium::from_reader(&out[..]).unwrap();
        assert_eq!(resp.schema_version, SCHEMA_VERSION);
        match resp.result {
            WireResult::Ok { step, handle } => {
                assert!(matches!(step, Step::Redirect(_)));
                assert_eq!(handle.schema_version, SCHEMA_VERSION);
            }
            WireResult::Err { message } => panic!("unexpected error: {message}"),
        }
    }

    #[test]
    fn process_bytes_garbage_returns_err_result() {
        let out = process_bytes(&[0xff, 0x00, 0x13, 0x37]);
        let resp: WireResponse = ciborium::from_reader(&out[..]).unwrap();
        assert!(matches!(resp.result, WireResult::Err { .. }));
    }

    #[test]
    fn c_abi_roundtrip_and_free() {
        let input = begin_envelope();
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        // SAFETY: valid input slice and out pointers.
        let rc = unsafe {
            cleverbase_process(
                input.as_ptr(),
                input.len(),
                &raw mut out_ptr,
                &raw mut out_len,
            )
        };
        assert_eq!(rc, 0);
        assert!(!out_ptr.is_null());
        assert!(out_len > 0);
        let out = unsafe { std::slice::from_raw_parts(out_ptr, out_len) }.to_vec();
        unsafe { cleverbase_free(out_ptr, out_len) };

        let resp: WireResponse = ciborium::from_reader(&out[..]).unwrap();
        assert!(matches!(resp.result, WireResult::Ok { .. }));
    }

    #[test]
    fn c_abi_null_args_return_nonzero() {
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc =
            unsafe { cleverbase_process(std::ptr::null(), 0, &raw mut out_ptr, &raw mut out_len) };
        assert_ne!(rc, 0);
    }

    #[test]
    fn process_bytes_dispatches_resume() {
        // Begin, extract the handle + state, then drive a Resume through the same dispatch.
        let resp: WireResponse =
            ciborium::from_reader(&process_bytes(&begin_envelope())[..]).unwrap();
        let (handle, state) = match resp.result {
            WireResult::Ok { handle, step } => match step {
                Step::Redirect(r) => (handle, r.state),
                other => panic!("expected redirect, got {other:?}"),
            },
            WireResult::Err { message } => panic!("begin failed: {message}"),
        };
        let resume = encode(&WireRequest {
            schema_version: SCHEMA_VERSION,
            op: WireOp::Resume {
                handle,
                input: ResumeInput::RedirectReturn {
                    code: "c".into(),
                    state,
                },
                ctx: HostContext {
                    now_unix: 1_700_000_000,
                    entropy: vec![7u8; 16],
                },
            },
        });
        let resp2: WireResponse = ciborium::from_reader(&process_bytes(&resume)[..]).unwrap();
        assert!(matches!(
            resp2.result,
            WireResult::Ok {
                step: Step::PerformHttp(_),
                ..
            }
        ));
    }

    #[test]
    fn process_bytes_begin_error_is_err_result() {
        // Empty client_id → core InvalidConfig → WireResult::Err (the dispatch Begin-error arm).
        let req = WireRequest {
            schema_version: SCHEMA_VERSION,
            op: WireOp::Begin {
                request: SigningRequest {
                    document: b"%PDF-1.7\nhi".to_vec(),
                    conformance_level: ConformanceLevel::BB,
                    expected_signer: None,
                    appearance: None,
                    signature_meta: None,
                },
                config: TrustServiceConfiguration {
                    environment: Environment::Acceptance,
                    csc_api: CscApi::V1Rsa,
                    client_id: String::new(),
                    client_secret: Secret::new("x"),
                    redirect_uri: "https://app.example/cb".into(),
                    tsa: None,
                },
                ctx: HostContext {
                    now_unix: 1_700_000_000,
                    entropy: vec![7u8; 16],
                },
            },
        };
        let resp: WireResponse = ciborium::from_reader(&process_bytes(&encode(&req))[..]).unwrap();
        assert!(matches!(resp.result, WireResult::Err { .. }));
    }

    #[test]
    fn free_null_pointer_is_noop() {
        // SAFETY: a null pointer is the documented no-op case.
        unsafe { cleverbase_free(std::ptr::null_mut(), 0) };
    }

    /// Drive the given CBOR `verify` request through the C-ABI and return the response bytes.
    fn drive_attestation_verify(input: &[u8]) -> Vec<u8> {
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        // SAFETY: valid input slice and out pointers.
        let rc = unsafe {
            cleverbase_attestation_verify(
                input.as_ptr(),
                input.len(),
                &raw mut out_ptr,
                &raw mut out_len,
            )
        };
        assert_eq!(rc, 0);
        assert!(!out_ptr.is_null());
        assert!(out_len > 0);
        let out = unsafe { std::slice::from_raw_parts(out_ptr, out_len) }.to_vec();
        unsafe { cleverbase_free(out_ptr, out_len) };
        out
    }

    #[test]
    fn attestation_verify_smoke_test_valid_end_to_end() {
        // The end-to-end VALID path through the real C-ABI: a conformant, trusted-issuer SD-JWT VC
        // (built by the shared test vectors) verifies to `VerifyOutcome::Ok { valid: true }`.
        use cleverbase_attestation::wire::{VerifyOutcome, VerifyResponse};
        let input = cleverbase_attestation::test_vectors::valid_sd_jwt_verify_request_cbor();
        let out = drive_attestation_verify(&input);
        let resp: VerifyResponse = ciborium::from_reader(&out[..]).unwrap();
        match resp.outcome {
            VerifyOutcome::Ok { result } => {
                assert!(result.valid, "expected VALID, reasons {:?}", result.reasons);
                assert!(result.disclosed_attributes.contains_key("given_name"));
            }
            VerifyOutcome::Err { message } => panic!("unexpected verify error: {message}"),
        }
    }

    #[test]
    fn attestation_verify_null_args_return_nonzero() {
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            cleverbase_attestation_verify(std::ptr::null(), 0, &raw mut out_ptr, &raw mut out_len)
        };
        assert_ne!(rc, 0);
    }

    #[test]
    fn attestation_verify_garbage_input_returns_err_outcome() {
        use cleverbase_attestation::wire::{VerifyOutcome, VerifyResponse};
        let out = drive_attestation_verify(&[0xffu8, 0x00, 0x13, 0x37]);
        let resp: VerifyResponse = ciborium::from_reader(&out[..]).unwrap();
        assert!(matches!(resp.outcome, VerifyOutcome::Err { .. }));
    }

    /// Drive the given CBOR set-level `verify_vp_token` request through the C-ABI and return the bytes.
    fn drive_attestation_verify_vp_token(input: &[u8]) -> Vec<u8> {
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        // SAFETY: valid input slice and out pointers.
        let rc = unsafe {
            cleverbase_attestation_verify_vp_token(
                input.as_ptr(),
                input.len(),
                &raw mut out_ptr,
                &raw mut out_len,
            )
        };
        assert_eq!(rc, 0);
        assert!(!out_ptr.is_null());
        assert!(out_len > 0);
        let out = unsafe { std::slice::from_raw_parts(out_ptr, out_len) }.to_vec();
        unsafe { cleverbase_free(out_ptr, out_len) };
        out
    }

    #[test]
    fn attestation_verify_vp_token_null_args_return_nonzero() {
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            cleverbase_attestation_verify_vp_token(
                std::ptr::null(),
                0,
                &raw mut out_ptr,
                &raw mut out_len,
            )
        };
        assert_ne!(rc, 0);
    }

    #[test]
    fn attestation_verify_vp_token_garbage_input_returns_err_outcome() {
        use cleverbase_attestation::wire::{WireVpTokenOutcome, WireVpTokenResponse};
        let out = drive_attestation_verify_vp_token(&[0xffu8, 0x00, 0x13, 0x37]);
        let resp: WireVpTokenResponse = ciborium::from_reader(&out[..]).unwrap();
        assert!(matches!(resp.outcome, WireVpTokenOutcome::Err { .. }));
    }

    /// Drive the given CBOR issuance request through the C-ABI and return the response bytes.
    fn drive_attestation_issuance(input: &[u8]) -> Vec<u8> {
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        // SAFETY: valid input slice and out pointers.
        let rc = unsafe {
            cleverbase_attestation_issuance(
                input.as_ptr(),
                input.len(),
                &raw mut out_ptr,
                &raw mut out_len,
            )
        };
        assert_eq!(rc, 0);
        assert!(!out_ptr.is_null());
        assert!(out_len > 0);
        let out = unsafe { std::slice::from_raw_parts(out_ptr, out_len) }.to_vec();
        unsafe { cleverbase_free(out_ptr, out_len) };
        out
    }

    #[test]
    fn attestation_issuance_none_backend_skips_end_to_end() {
        // The gated default through the real C-ABI: a `None` issuer backend → a clean Skipped outcome
        // (never a failure — FR-008), exercising the additive issuance surface.
        use cleverbase_attestation::issuance::wire::{
            IssuanceOutcome, IssuanceResponse, WireObtainStep,
        };
        let input = cleverbase_attestation::test_vectors::skipped_issuance_request_cbor();
        let out = drive_attestation_issuance(&input);
        let resp: IssuanceResponse = ciborium::from_reader(&out[..]).unwrap();
        match resp.outcome {
            IssuanceOutcome::Obtain { step, session } => {
                assert_eq!(step, WireObtainStep::Skipped);
                assert!(session.is_none());
            }
            other => panic!("expected a Skipped obtain outcome, got {other:?}"),
        }
    }

    #[test]
    fn attestation_issuance_null_args_return_nonzero() {
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            cleverbase_attestation_issuance(std::ptr::null(), 0, &raw mut out_ptr, &raw mut out_len)
        };
        assert_ne!(rc, 0);
    }

    #[test]
    fn attestation_issuance_garbage_input_returns_err_outcome() {
        use cleverbase_attestation::issuance::wire::{IssuanceOutcome, IssuanceResponse};
        let out = drive_attestation_issuance(&[0xffu8, 0x00, 0x13, 0x37]);
        let resp: IssuanceResponse = ciborium::from_reader(&out[..]).unwrap();
        assert!(matches!(resp.outcome, IssuanceOutcome::Err { .. }));
    }
}
