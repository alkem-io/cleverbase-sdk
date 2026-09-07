"""Tests for the Cleverbase Python binding.

The binding returns CBOR `{handle, step}` results; the test only decodes them (it never hand-builds
CBOR), exercising the real Rust core through PyO3.
"""

import json
from base64 import b64encode
from pathlib import Path
from typing import TypedDict, cast

import cbor2
import cleverbase
import pytest

NOW = 1_700_000_000
ENTROPY = bytes(range(16))
PDF = b"%PDF-1.7\nminimal"
REPO_ROOT = Path(__file__).resolve().parents[3]


class TsaEffect(TypedDict):
    """Typed subset of the emitted host HTTP effect used by this contract test."""

    kind: str
    url: str
    headers: list[tuple[str, str]]
    body: bytes


def drive_to_tsa_effect() -> TsaEffect:
    document = (REPO_ROOT / "tests/fixtures/signing/binding-input.pdf").read_bytes()
    certificate = b64encode(
        (REPO_ROOT / "tests/fixtures/pki/signer-rsa.cert.der").read_bytes()
    ).decode()
    sign_hash_response = (
        REPO_ROOT / "tests/fixtures/signing/rsa_sign_hash_response.json"
    ).read_bytes()

    result = cbor2.loads(
        cleverbase.begin_signing(
            document,
            "acceptance",
            "v1_rsa",
            "client-123",
            "secret",
            "https://app.example/cb",
            "B-T",
            NOW,
            ENTROPY,
            tsa_url="https://tsa.example/rfc3161",
            tsa_auth="Basic public-test-credentials",
            tsa_policy_oid="1.2.3.4",
        )
    )
    result = cbor2.loads(
        cleverbase.resume_redirect(
            result["handle"], "service-code", result["step"]["state"], NOW, ENTROPY
        )
    )
    for response in (
        {"access_token": "bearer", "token_type": "Bearer"},
        {"credentialIDs": ["cred-1"]},
        {
            "key": {"status": "enabled", "algo": ["1.2.840.113549.1.1.1"], "len": 2048},
            "cert": {
                "status": "valid",
                "certificates": [certificate],
                "subjectDN": "CN=Jane Doe,serialNumber=PNONL-123",
                "serialNumber": "PNONL-123",
            },
            "SCAL": "2",
        },
    ):
        result = cbor2.loads(
            cleverbase.resume_http(
                result["handle"], 200, json.dumps(response).encode(), NOW, ENTROPY
            )
        )
    result = cbor2.loads(
        cleverbase.resume_redirect(
            result["handle"], "credential-code", result["step"]["state"], NOW, ENTROPY
        )
    )
    result = cbor2.loads(
        cleverbase.resume_http(
            result["handle"],
            200,
            b'{"access_token":"SAD","token_type":"SAD"}',
            NOW,
            ENTROPY,
        )
    )
    final = cbor2.loads(
        cleverbase.resume_http(result["handle"], 200, sign_hash_response, NOW, ENTROPY)
    )
    return cast("TsaEffect", final["step"])


def test_schema_version_exposed() -> None:
    assert isinstance(cleverbase.SCHEMA_VERSION, int)
    assert cleverbase.SCHEMA_VERSION >= 1


def test_validate_config_accepts_valid_inputs_and_rejects_missing_client_id() -> None:
    cleverbase.validate_config(
        "acceptance",
        "v1_rsa",
        "client-123",
        "secret",
        "https://app.example/cb",
        "https://tsa.example/rfc3161",
    )

    with pytest.raises(ValueError):
        cleverbase.validate_config(
            "acceptance",
            "v1_rsa",
            "",
            "secret",
            "https://app.example/cb",
            "https://tsa.example/rfc3161",
        )


def test_config_options_match_the_go_binding_surface() -> None:
    cleverbase.validate_config(
        "acceptance",
        "v1_rsa",
        "client-123",
        "secret",
        "https://app.example/cb",
        tsa_url="https://tsa.example/rfc3161",
        upstream_base_url="http://localhost:9000/stub",
        tsa_auth="Basic public-test-credentials",
        tsa_policy_oid="1.2.3.4",
    )

    with pytest.raises(ValueError):
        cleverbase.validate_config(
            "acceptance",
            "v1_rsa",
            "client-123",
            "secret",
            "https://app.example/cb",
            upstream_base_url="http://not-loopback.example/stub",
        )

    out = cleverbase.begin_signing(
        PDF,
        "acceptance",
        "v1_rsa",
        "client-123",
        "secret",
        "https://app.example/cb",
        "B-T",
        NOW,
        ENTROPY,
        tsa_url="https://tsa.example/rfc3161",
        upstream_base_url="http://localhost:9000/stub",
        tsa_auth="Basic public-test-credentials",
        tsa_policy_oid="1.2.3.4",
    )
    resp = cbor2.loads(out)
    assert resp["step"]["url"].startswith("http://localhost:9000/stub/oauth2/authorize?")


def test_tsa_auth_and_policy_reach_the_timestamp_request() -> None:
    step = drive_to_tsa_effect()

    assert step["kind"] == "perform_http"
    assert step["url"] == "https://tsa.example/rfc3161"
    assert dict(step["headers"])["Authorization"] == "Basic public-test-credentials"
    assert bytes.fromhex("06032a0304") in step["body"]  # DER OBJECT IDENTIFIER 1.2.3.4


@pytest.mark.parametrize(
    "tsa_url",
    [
        "not a URL",
        "ftp://tsa.example/tsr",
        "https://user:password@tsa.example/tsr",
        "https://tsa.example/tsr#response",
        "https://tsa.example:0/tsr",
    ],
)
def test_validate_config_rejects_invalid_tsa_urls(tsa_url: str) -> None:
    with pytest.raises(ValueError):
        cleverbase.validate_config(
            "acceptance",
            "v1_rsa",
            "client-123",
            "secret",
            "https://app.example/cb",
            tsa_url=tsa_url,
        )


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
