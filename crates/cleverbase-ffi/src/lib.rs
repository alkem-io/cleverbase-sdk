//! Stable C ABI over `cleverbase-core` (contracts/sdk-api.md).
//!
//! Two functions, mirroring Cleverbase's own `scal3` boundary: a coarse CBOR-in / CBOR-out
//! `cleverbase_process`, and `cleverbase_free` to release the returned buffer. The CBOR envelope
//! is versioned (`schema_version`), so the ABI stays stable within a SemVer major.

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
    unsafe {
        if in_ptr.is_null() || out_ptr.is_null() || out_len.is_null() {
            return 1;
        }
        // Initialize the outputs so a consumer that inspects them on a non-zero return (e.g. the
        // panic path below) sees a null/empty buffer, never uninitialized memory.
        *out_ptr = std::ptr::null_mut();
        *out_len = 0;
        let input = std::slice::from_raw_parts(in_ptr, in_len);
        // A panic unwinding across the C ABI is undefined behavior; contain it and report status 2.
        let bytes = match std::panic::catch_unwind(|| process_bytes(input)) {
            Ok(bytes) => bytes,
            Err(_) => return 2,
        };

        // Hand ownership to the caller as an exact-capacity boxed slice (cap == len).
        let boxed = bytes.into_boxed_slice();
        let len = boxed.len();
        let ptr = Box::into_raw(boxed).cast::<u8>();
        *out_ptr = ptr;
        *out_len = len;
        0
    }
}

/// Free a buffer previously returned by [`cleverbase_process`].
///
/// # Safety
/// `ptr`/`len` must be exactly what a prior `cleverbase_process` call wrote, freed at most once.
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
}
