# `cleverbase`

## `SCHEMA_VERSION: int`

## `begin_signing`

```python
def begin_signing(document: bytes, environment: str, csc_api: str, client_id: str, client_secret: str, redirect_uri: str, conformance: str, now_unix: int, entropy: bytes, tsa_url: str | None = ..., options_json: str | None = ...) -> bytes
```

## `resume_redirect`

```python
def resume_redirect(handle: bytes, code: str, state: str, now_unix: int, entropy: bytes) -> bytes
```

## `resume_redirect_error`

```python
def resume_redirect_error(handle: bytes, error: str, state: str, now_unix: int, entropy: bytes) -> bytes
```

## `resume_http`

```python
def resume_http(handle: bytes, status: int, body: bytes, now_unix: int, entropy: bytes) -> bytes
```
