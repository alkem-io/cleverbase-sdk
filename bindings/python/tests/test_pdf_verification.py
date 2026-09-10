"""PDF verification and host-context contract tests for the Python binding."""

from pathlib import Path

import cleverbase
import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
VALID_BT_PDF = REPO_ROOT / "tests/fixtures/pades-bt/rsa.pdf"
LEGACY_BYTE_RANGE_PDF = (
    REPO_ROOT / "tests/fixtures/pades-conformance/cleverbase-acceptance-dev-2026-09-10.pdf"
)
YEAR_0000_START = -62_167_219_200
YEAR_9999_END = 253_402_300_799


def test_verify_pdf_returns_typed_valid_verdict() -> None:
    verdict = cleverbase.verify_pdf(VALID_BT_PDF.read_bytes())

    assert verdict == {
        "integrity": True,
        "profile": "B-T",
        "signer": {
            "serial": "07FB0DA8384404C33517B852CFE79F04C5006AC1",
            "cn": "Jane Doe",
        },
        "reasons": [],
    }


@pytest.mark.parametrize(
    ("document", "reason"),
    [
        (b"not a PDF", "not_pdf"),
        (LEGACY_BYTE_RANGE_PDF.read_bytes(), "malformed_byte_range"),
    ],
)
def test_verify_pdf_returns_typed_invalid_verdict(document: bytes, reason: str) -> None:
    verdict = cleverbase.verify_pdf(document)

    assert verdict == {
        "integrity": False,
        "profile": None,
        "signer": None,
        "reasons": [reason],
    }


@pytest.mark.parametrize("now_unix", [YEAR_0000_START, YEAR_9999_END])
def test_begin_accepts_host_context_year_boundaries(now_unix: int) -> None:
    response = cleverbase.begin_signing(
        b"%PDF-1.7\nminimal",
        "acceptance",
        "v1_rsa",
        "client-123",
        "secret",
        "https://app.example/cb",
        "B-B",
        now_unix,
        bytes(range(16)),
    )

    assert isinstance(response, bytes)


@pytest.mark.parametrize(
    ("now_unix", "entropy"),
    [
        (YEAR_0000_START - 1, bytes(range(16))),
        (YEAR_9999_END + 1, bytes(range(16))),
        (1_700_000_000, bytes(range(15))),
    ],
)
def test_begin_rejects_invalid_host_context(now_unix: int, entropy: bytes) -> None:
    with pytest.raises(ValueError):
        cleverbase.begin_signing(
            b"%PDF-1.7\nminimal",
            "acceptance",
            "v1_rsa",
            "client-123",
            "secret",
            "https://app.example/cb",
            "B-B",
            now_unix,
            entropy,
        )
