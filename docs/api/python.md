# `cleverbase`

## `SCHEMA_VERSION: int`

## `PDFSigner`

```python
class PDFSigner(TypedDict)
```

## `serial: str`

## `cn: str`

## `PDFVerification`

```python
class PDFVerification(TypedDict)
```

## `integrity: bool`

## `profile: str | None`

## `signer: PDFSigner | None`

## `reasons: list[str]`

## `validate_config`

```python
def validate_config(environment: str, csc_api: str, client_id: str, client_secret: str, redirect_uri: str, tsa_url: str | None = ..., *, upstream_base_url: str | None = ..., tsa_auth: str | None = ..., tsa_policy_oid: str | None = ...) -> None
```

## `begin_signing`

```python
def begin_signing(document: bytes, environment: str, csc_api: str, client_id: str, client_secret: str, redirect_uri: str, conformance: str, now_unix: Annotated[int, "UTC year 0000..9999"], entropy: Annotated[bytes, "at least 16 fresh random bytes for this call"], tsa_url: str | None = ..., options_json: str | None = ..., *, upstream_base_url: str | None = ..., tsa_auth: str | None = ..., tsa_policy_oid: str | None = ...) -> bytes
```

## `resume_redirect`

```python
def resume_redirect(handle: bytes, code: str, state: str, now_unix: Annotated[int, "UTC year 0000..9999"], entropy: Annotated[bytes, "at least 16 fresh random bytes for this call"]) -> bytes
```

## `resume_redirect_error`

```python
def resume_redirect_error(handle: bytes, error: str, state: str, now_unix: Annotated[int, "UTC year 0000..9999"], entropy: Annotated[bytes, "at least 16 fresh random bytes for this call"]) -> bytes
```

## `resume_http`

```python
def resume_http(handle: bytes, status: int, body: bytes, now_unix: Annotated[int, "UTC year 0000..9999"], entropy: Annotated[bytes, "at least 16 fresh random bytes for this call"]) -> bytes
```

## `verify_pdf`

```python
def verify_pdf(document: bytes) -> PDFVerification
```

## `attestation_verify`

```python
def attestation_verify(request: bytes) -> bytes
```

## `attestation_verify_vp_token`

```python
def attestation_verify_vp_token(request: bytes) -> bytes
```

## `attestation_issuance`

```python
def attestation_issuance(request: bytes) -> bytes
```
