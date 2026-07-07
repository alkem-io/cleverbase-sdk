"""Tests for the Cleverbase Python binding's EUDI attestation surface.

Unlike the signing surface, attestation is CBOR-in / CBOR-out: the test hand-builds a well-formed
CBOR `VerifyRequest` / `IssuanceRequest` and decodes the CBOR response, exercising the real Rust
attestation core through PyO3. ciborium externally-tagged enums serialize as single-key dicts (e.g.
`{"ok": ...}`); struct fields are literal snake_case.
"""

import cbor2
import cleverbase


def test_verify_round_trip_runs_verifier() -> None:
    # A well-formed request with a bogus presentation and no anchors: the verifier RUNS (proving the
    # full CBOR round-trip) and returns an INVALID verdict rather than an error.
    req = {
        "schema_version": 5,
        "presentation": {"sd_jwt_vc": {"presentation": "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ4In0.AAAA~"}},
        "policy": {"formats": [], "qualified_gate": False, "status_reachability": "fail_closed"},
        "anchors": [],
        "context": {"now_unix": 0, "role": "pid", "statuses": ["no_status"]},
    }
    resp = cbor2.loads(cleverbase.attestation_verify(cbor2.dumps(req)))
    assert resp["schema_version"] == 5
    outcome = resp["outcome"]
    # Exactly one of ok / err.
    assert ("ok" in outcome) ^ ("err" in outcome)
    # The verifier ran (ok outcome); the bogus presentation + empty anchors ⇒ INVALID verdict.
    assert "ok" in outcome
    assert outcome["ok"]["result"]["valid"] is False


def test_verify_garbage_yields_err_outcome() -> None:
    # A structurally invalid request decodes to an `err` outcome inside a well-formed response
    # envelope (the error rides inside the response; the boundary never raises).
    resp = cbor2.loads(cleverbase.attestation_verify(cbor2.dumps(0)))
    assert resp["schema_version"] == 5
    assert "err" in resp["outcome"]


def test_verify_vp_token_round_trip_runs_set_level_verifier() -> None:
    # A well-formed set-level WireVpTokenRequest with a bogus presentation and no anchors: the set-level
    # verifier RUNS (proving the round-trip through the new symbol) and returns an UNSATISFIED verdict.
    req = {
        "schema_version": 5,
        "request": {
            "dcql": {
                "query_json": '{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}]}'
            },
            "nonce": bytes([7] * 16),
            "audience": "https://verifier.example/cb",
            "response_uri": "https://verifier.example/cb/response",
        },
        "vp_token": {
            "pid": [{"sd_jwt_vc": {"presentation": "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ4In0.AAAA~"}}]
        },
        "policy": {"formats": [], "qualified_gate": False, "status_reachability": "fail_closed"},
        "anchors": [],
        "now_unix": 0,
        "role": "pid",
        "statuses": {"pid": [["no_status"]]},
    }
    resp = cbor2.loads(cleverbase.attestation_verify_vp_token(cbor2.dumps(req)))
    assert resp["schema_version"] == 5
    outcome = resp["outcome"]
    assert ("ok" in outcome) ^ ("err" in outcome)
    assert "ok" in outcome
    # A bogus presentation + no anchors cannot satisfy the required credential → not satisfied.
    assert outcome["ok"]["result"]["satisfied"] is False


def test_verify_vp_token_garbage_yields_err_outcome() -> None:
    resp = cbor2.loads(cleverbase.attestation_verify_vp_token(cbor2.dumps(0)))
    assert resp["schema_version"] == 5
    assert "err" in resp["outcome"]


def test_issuance_garbage_yields_err_outcome() -> None:
    resp = cbor2.loads(cleverbase.attestation_issuance(bytes([0xFF, 0x00])))
    assert resp["schema_version"] == 1
    assert "err" in resp["outcome"]
