# Type stub for the Cleverbase PyO3 extension module.
#
# The runtime module is a compiled Rust extension (`src/lib.rs`); this stub mirrors its public
# surface so the test suite and integrators type-check against real signatures under strict mypy.
# Every function returns the CBOR-encoded `{handle, step}` envelope as `bytes` (callers only ever
# *decode* CBOR) and raises `ValueError` on invalid input. Runtime docstrings live on the PyO3
# definitions, not here: PEP 484 stubs carry types only, no docstrings (ruff PYI021).
#
# Keep this stub in lockstep with the `#[pyfunction]` signatures in `src/lib.rs`.

SCHEMA_VERSION: int

def begin_signing(
    document: bytes,
    environment: str,
    csc_api: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    conformance: str,
    now_unix: int,
    entropy: bytes,
    tsa_url: str | None = ...,
    options_json: str | None = ...,
) -> bytes: ...
def resume_redirect(
    handle: bytes,
    code: str,
    state: str,
    now_unix: int,
    entropy: bytes,
) -> bytes: ...
def resume_redirect_error(
    handle: bytes,
    error: str,
    state: str,
    now_unix: int,
    entropy: bytes,
) -> bytes: ...
def resume_http(
    handle: bytes,
    status: int,
    body: bytes,
    now_unix: int,
    entropy: bytes,
) -> bytes: ...
def attestation_verify(request: bytes) -> bytes: ...
def attestation_issuance(request: bytes) -> bytes: ...
