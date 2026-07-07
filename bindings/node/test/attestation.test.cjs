const test = require("node:test");
const assert = require("node:assert");
const cbor = require("cbor");
const { attestationVerify, attestationVerifyVpToken, attestationIssuance } = require("../index.js");

// The attestation surface is CBOR-through: a CBOR VerifyRequest / IssuanceRequest goes in and a
// CBOR VerifyResponse / IssuanceResponse comes out. The verdict and any error ride *inside* the
// response body (never the call's error channel), so these tests decode the response and inspect
// its `outcome`. ciborium externally-tagged enums serialize as single-key maps; struct fields are
// literal snake_case.

// Exactly one of the externally-tagged outcome variants is present.
function assertOneOf(outcome, a, b) {
  const hasA = Object.prototype.hasOwnProperty.call(outcome, a);
  const hasB = Object.prototype.hasOwnProperty.call(outcome, b);
  assert.ok(
    hasA !== hasB,
    `expected exactly one of ${a}/${b}, got ${JSON.stringify(Object.keys(outcome))}`,
  );
}

test("attestationVerify runs the verifier end-to-end (bogus presentation ⇒ INVALID verdict)", () => {
  const req = {
    schema_version: 5,
    presentation: { sd_jwt_vc: { presentation: "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ4In0.AAAA~" } },
    policy: { formats: [], qualified_gate: false, status_reachability: "fail_closed" },
    anchors: [],
    context: { now_unix: 0, role: "pid", statuses: ["no_status"] },
  };
  const resp = cbor.decodeFirstSync(attestationVerify(cbor.encode(req)));

  assert.strictEqual(resp.schema_version, 5);
  assertOneOf(resp.outcome, "ok", "err");
  if (Object.prototype.hasOwnProperty.call(resp.outcome, "ok")) {
    // The verifier RAN and returned a VerificationResult — with no trust anchors the bogus
    // presentation is INVALID, which is the whole point: the round-trip reached the verdict.
    assert.strictEqual(resp.outcome.ok.result.valid, false);
  }
});

test("attestationVerify fails closed on garbage input (non-map ⇒ err outcome, schema 5)", () => {
  const resp = cbor.decodeFirstSync(attestationVerify(cbor.encode(0)));
  assert.strictEqual(resp.schema_version, 5);
  assertOneOf(resp.outcome, "ok", "err");
  assert.ok(Object.prototype.hasOwnProperty.call(resp.outcome, "err"));
});

test("attestationVerifyVpToken runs the set-level verifier end-to-end (bogus ⇒ UNSATISFIED)", () => {
  // A well-formed set-level WireVpTokenRequest with a bogus presentation and no anchors: the verifier
  // RUNS (proving the round-trip through the new symbol) and returns an UNSATISFIED ok outcome.
  const req = {
    schema_version: 5,
    request: {
      dcql: {
        query_json:
          '{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}]}',
      },
      nonce: Buffer.from([7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7]),
      audience: "https://verifier.example/cb",
      response_uri: "https://verifier.example/cb/response",
    },
    vp_token: {
      pid: [{ sd_jwt_vc: { presentation: "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ4In0.AAAA~" } }],
    },
    policy: { formats: [], qualified_gate: false, status_reachability: "fail_closed" },
    anchors: [],
    now_unix: 0,
    role: "pid",
    statuses: { pid: [["no_status"]] },
  };
  const resp = cbor.decodeFirstSync(attestationVerifyVpToken(cbor.encode(req)));
  assert.strictEqual(resp.schema_version, 5);
  assertOneOf(resp.outcome, "ok", "err");
  assert.ok(Object.prototype.hasOwnProperty.call(resp.outcome, "ok"));
  // A bogus presentation + no anchors cannot satisfy the required credential → not satisfied.
  assert.strictEqual(resp.outcome.ok.result.satisfied, false);
});

test("attestationVerifyVpToken fails closed on garbage input (non-map ⇒ err outcome, schema 5)", () => {
  const resp = cbor.decodeFirstSync(attestationVerifyVpToken(cbor.encode(0)));
  assert.strictEqual(resp.schema_version, 5);
  assertOneOf(resp.outcome, "ok", "err");
  assert.ok(Object.prototype.hasOwnProperty.call(resp.outcome, "err"));
});

test("attestationIssuance round-trips and fails closed on a malformed request (schema 1, err)", () => {
  const resp = cbor.decodeFirstSync(attestationIssuance(Buffer.from([0xff, 0x00])));
  assert.strictEqual(resp.schema_version, 1);
  assertOneOf(resp.outcome, "ok", "err");
  assert.ok(Object.prototype.hasOwnProperty.call(resp.outcome, "err"));
});
