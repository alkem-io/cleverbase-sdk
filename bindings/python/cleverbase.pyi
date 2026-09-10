# Type stub for the Cleverbase PyO3 extension module.
#
# The runtime module is a compiled Rust extension (`src/lib.rs`); this stub mirrors its public
# surface so the test suite and integrators type-check against real signatures under strict mypy.
# Signing-flow functions return the CBOR-encoded handle/step envelope as bytes; verification returns
# the typed verdict below. Invalid API input raises ValueError. Runtime docstrings live on the PyO3
# definitions, not here: PEP 484 stubs carry types only, no docstrings (ruff PYI021).
#
# Keep this stub in lockstep with the pyfunction signatures in src/lib.rs.

from typing import Annotated, TypedDict

SCHEMA_VERSION: int

# Typing-only shapes: verify_pdf returns a runtime dict; the compiled module does not export these
# names as Python classes (tracked for a package-layout follow-up in #59).
class PDFSigner(TypedDict):
    serial: str
    cn: str

class PDFVerification(TypedDict):
    integrity: bool
    profile: str | None
    signer: PDFSigner | None
    reasons: list[str]

def validate_config(
    environment: str,
    csc_api: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    tsa_url: str | None = ...,
    *,
    upstream_base_url: str | None = ...,
    tsa_auth: str | None = ...,
    tsa_policy_oid: str | None = ...,
) -> None: ...
def begin_signing(
    document: bytes,
    environment: str,
    csc_api: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    conformance: str,
    now_unix: Annotated[int, "UTC year 0000..9999"],
    entropy: Annotated[bytes, "at least 16 fresh random bytes for this call"],
    tsa_url: str | None = ...,
    options_json: str | None = ...,
    *,
    upstream_base_url: str | None = ...,
    tsa_auth: str | None = ...,
    tsa_policy_oid: str | None = ...,
) -> bytes: ...
def resume_redirect(
    handle: bytes,
    code: str,
    state: str,
    now_unix: Annotated[int, "UTC year 0000..9999"],
    entropy: Annotated[bytes, "at least 16 fresh random bytes for this call"],
) -> bytes: ...
def resume_redirect_error(
    handle: bytes,
    error: str,
    state: str,
    now_unix: Annotated[int, "UTC year 0000..9999"],
    entropy: Annotated[bytes, "at least 16 fresh random bytes for this call"],
) -> bytes: ...
def resume_http(
    handle: bytes,
    status: int,
    body: bytes,
    now_unix: Annotated[int, "UTC year 0000..9999"],
    entropy: Annotated[bytes, "at least 16 fresh random bytes for this call"],
) -> bytes: ...
def verify_pdf(document: bytes) -> PDFVerification: ...
def attestation_verify(request: bytes) -> bytes: ...
def attestation_verify_vp_token(request: bytes) -> bytes: ...
def attestation_issuance(request: bytes) -> bytes: ...
