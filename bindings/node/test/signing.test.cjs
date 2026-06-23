const test = require("node:test");
const assert = require("node:assert");
const cbor = require("cbor");
const { beginSigning, resumeRedirect, resumeRedirectError } = require("../index.js");

const NOW = 1_700_000_000;
const ENTROPY = Buffer.from(Array.from({ length: 16 }, (_, i) => i));
const PDF = Buffer.from("%PDF-1.7\nminimal");

test("begin returns a service-scope redirect", () => {
  const out = beginSigning(
    PDF,
    "acceptance",
    "v1_rsa",
    "client-123",
    "secret",
    "https://app.example/cb",
    "B-B",
    NOW,
    ENTROPY,
    null,
  );
  const resp = cbor.decodeFirstSync(out);
  assert.strictEqual(resp.step.kind, "redirect");
  assert.ok(resp.step.url.includes("scope=service"));
  assert.ok(Buffer.isBuffer(resp.handle));
});

test("resume redirect emits the token exchange", () => {
  const out = beginSigning(
    PDF,
    "acceptance",
    "v1_rsa",
    "client-123",
    "secret",
    "https://app.example/cb",
    "B-B",
    NOW,
    ENTROPY,
    null,
  );
  const resp = cbor.decodeFirstSync(out);
  const out2 = resumeRedirect(resp.handle, "code-xyz", resp.step.state, NOW, ENTROPY);
  const resp2 = cbor.decodeFirstSync(out2);
  assert.strictEqual(resp2.step.kind, "perform_http");
  assert.ok(resp2.step.url.endsWith("/oauth2/token"));
});

test("invalid document yields a failed step", () => {
  const out = beginSigning(
    Buffer.from("not a pdf"),
    "acceptance",
    "v1_rsa",
    "client-123",
    "secret",
    "https://app.example/cb",
    "B-B",
    NOW,
    ENTROPY,
    null,
  );
  const resp = cbor.decodeFirstSync(out);
  assert.strictEqual(resp.step.kind, "failed");
  assert.strictEqual(resp.step.evidence.outcome, "invalid_document");
});

test("redirect error (signer decline) yields a declined outcome", () => {
  const out = beginSigning(
    PDF,
    "acceptance",
    "v1_rsa",
    "client-123",
    "secret",
    "https://app.example/cb",
    "B-B",
    NOW,
    ENTROPY,
    null,
  );
  const resp = cbor.decodeFirstSync(out);
  const out2 = resumeRedirectError(resp.handle, "access_denied", resp.step.state, NOW, ENTROPY);
  const resp2 = cbor.decodeFirstSync(out2);
  assert.strictEqual(resp2.step.kind, "failed");
  assert.strictEqual(resp2.step.evidence.outcome, "declined");
});

test("invalid enum values and bad handles throw", () => {
  assert.throws(() =>
    beginSigning(PDF, "acceptance", "v1_rsa", "c", "s", "https://a/cb", "NOPE", NOW, ENTROPY, null),
  );
  assert.throws(() =>
    beginSigning(PDF, "NOPE", "v1_rsa", "c", "s", "https://a/cb", "B-B", NOW, ENTROPY, null),
  );
  assert.throws(() => resumeRedirect(Buffer.from("bad handle"), "c", "s", NOW, ENTROPY));
  assert.throws(() =>
    resumeRedirectError(Buffer.from("bad handle"), "access_denied", "s", NOW, ENTROPY),
  );
  assert.throws(() =>
    beginSigning(
      PDF,
      "acceptance",
      "v1_rsa",
      "c",
      "s",
      "https://a/cb",
      "B-B",
      NOW,
      ENTROPY,
      null,
      "{not json",
    ),
  );
});

test("begin accepts request options (expected_signer / appearance / signature_meta)", () => {
  const options = JSON.stringify({
    expected_signer: { match_on: "certificate_serial_number", value: "PNONL-123" },
    appearance: {
      page: 1,
      rect: { x: 50, y: 50, w: 200, h: 80 },
      show: { signer_name: true, signing_time: true },
    },
    signature_meta: { reason: "Approval", location: "NL" },
  });
  const out = beginSigning(
    PDF,
    "acceptance",
    "v1_rsa",
    "client-123",
    "secret",
    "https://app.example/cb",
    "B-B",
    NOW,
    ENTROPY,
    null,
    options,
  );
  const resp = cbor.decodeFirstSync(out);
  assert.strictEqual(resp.step.kind, "redirect");
});
