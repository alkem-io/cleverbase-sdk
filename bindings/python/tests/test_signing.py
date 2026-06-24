"""Tests for the Cleverbase Python binding.

The binding returns CBOR `{handle, step}` results; the test only decodes them (it never hand-builds
CBOR), exercising the real Rust core through PyO3.
"""

import json

import cbor2
import cleverbase
import pytest

NOW = 1_700_000_000
ENTROPY = bytes(range(16))
PDF = b"%PDF-1.7\nminimal"


def test_schema_version_exposed() -> None:
    assert isinstance(cleverbase.SCHEMA_VERSION, int)
    assert cleverbase.SCHEMA_VERSION >= 1


def test_begin_returns_service_redirect() -> None:
    out = cleverbase.begin_signing(
        PDF,
        "acceptance",
        "v1_rsa",
        "client-123",
        "secret",
        "https://app.example/cb",
        "B-B",
        NOW,
        ENTROPY,
    )
    resp = cbor2.loads(out)
    assert resp["step"]["kind"] == "redirect"
    assert "scope=service" in resp["step"]["url"]
    assert isinstance(resp["handle"], (bytes, bytearray))


def test_resume_redirect_emits_token_exchange() -> None:
    out = cleverbase.begin_signing(
        PDF,
        "acceptance",
        "v1_rsa",
        "client-123",
        "secret",
        "https://app.example/cb",
        "B-B",
        NOW,
        ENTROPY,
    )
    resp = cbor2.loads(out)
    handle, state = resp["handle"], resp["step"]["state"]

    out2 = cleverbase.resume_redirect(handle, "code-xyz", state, NOW, ENTROPY)
    resp2 = cbor2.loads(out2)
    assert resp2["step"]["kind"] == "perform_http"
    assert resp2["step"]["url"].endswith("/oauth2/token")


def test_resume_redirect_error_yields_declined() -> None:
    out = cleverbase.begin_signing(
        PDF,
        "acceptance",
        "v1_rsa",
        "client-123",
        "secret",
        "https://app.example/cb",
        "B-B",
        NOW,
        ENTROPY,
    )
    resp = cbor2.loads(out)
    handle, state = resp["handle"], resp["step"]["state"]

    out2 = cleverbase.resume_redirect_error(handle, "access_denied", state, NOW, ENTROPY)
    resp2 = cbor2.loads(out2)
    assert resp2["step"]["kind"] == "failed"
    assert resp2["step"]["evidence"]["outcome"] == "declined"


def test_begin_with_options_json() -> None:
    options = json.dumps(
        {
            "expected_signer": {"match_on": "certificate_serial_number", "value": "PNONL-123"},
            "appearance": {
                "page": 1,
                "rect": {"x": 50, "y": 50, "w": 200, "h": 80},
                "show": {"signer_name": True, "signing_time": True},
            },
            "signature_meta": {"reason": "Approval", "location": "NL"},
        }
    )
    out = cleverbase.begin_signing(
        PDF,
        "acceptance",
        "v1_rsa",
        "client-123",
        "secret",
        "https://app.example/cb",
        "B-B",
        NOW,
        ENTROPY,
        None,
        options,
    )
    resp = cbor2.loads(out)
    assert resp["step"]["kind"] == "redirect"


def test_invalid_conformance_raises() -> None:
    with pytest.raises(ValueError):
        cleverbase.begin_signing(
            PDF,
            "acceptance",
            "v1_rsa",
            "c",
            "s",
            "https://app.example/cb",
            "NOPE",
            NOW,
            ENTROPY,
        )


def test_invalid_environment_raises() -> None:
    with pytest.raises(ValueError):
        cleverbase.begin_signing(
            PDF,
            "NOPE",
            "v1_rsa",
            "c",
            "s",
            "https://app.example/cb",
            "B-B",
            NOW,
            ENTROPY,
        )


def test_resume_with_bad_handle_raises() -> None:
    with pytest.raises(ValueError):
        cleverbase.resume_redirect(b"not a valid handle", "code", "state", NOW, ENTROPY)
    with pytest.raises(ValueError):
        cleverbase.resume_http(b"not a valid handle", 200, b"{}", NOW, ENTROPY)
    with pytest.raises(ValueError):
        cleverbase.resume_redirect_error(b"not a valid handle", "access_denied", "s", NOW, ENTROPY)


def test_invalid_options_json_raises() -> None:
    with pytest.raises(ValueError):
        cleverbase.begin_signing(
            PDF,
            "acceptance",
            "v1_rsa",
            "c",
            "s",
            "https://app.example/cb",
            "B-B",
            NOW,
            ENTROPY,
            None,
            "{not json",
        )


def test_invalid_document_is_failed_step() -> None:
    out = cleverbase.begin_signing(
        b"not a pdf",
        "acceptance",
        "v1_rsa",
        "client-123",
        "secret",
        "https://app.example/cb",
        "B-B",
        NOW,
        ENTROPY,
    )
    resp = cbor2.loads(out)
    assert resp["step"]["kind"] == "failed"
    assert resp["step"]["evidence"]["outcome"] == "invalid_document"
