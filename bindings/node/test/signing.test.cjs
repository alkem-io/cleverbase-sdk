const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const cbor = require("cbor");
const {
  beginSigning,
  resumeHttp,
  resumeRedirect,
  resumeRedirectError,
  validateConfig,
} = require("./load-sdk.cjs");

const NOW = 1_700_000_000;
const ENTROPY = Buffer.from(Array.from({ length: 16 }, (_, i) => i));
const PDF = Buffer.from("%PDF-1.7\nminimal");
const REPO_ROOT = path.resolve(__dirname, "../../..");

function driveToTsaEffect() {
  const document = fs.readFileSync(
    path.join(REPO_ROOT, "tests/fixtures/signing/binding-input.pdf"),
  );
  const certificate = fs
    .readFileSync(path.join(REPO_ROOT, "tests/fixtures/pki/signer-rsa.cert.der"))
    .toString("base64");
  const signHashResponse = fs.readFileSync(
    path.join(REPO_ROOT, "tests/fixtures/signing/rsa_sign_hash_response.json"),
  );
  const decode = (value) => cbor.decodeFirstSync(value);
  const resumeJson = (result, response) =>
    decode(resumeHttp(result.handle, 200, Buffer.from(JSON.stringify(response)), NOW, ENTROPY));

  let result = decode(
    beginSigning(
      document,
      "acceptance",
      "v1_rsa",
      "client-123",
      "secret",
      "https://app.example/cb",
      "B-T",
      NOW,
      ENTROPY,
      "https://tsa.example/rfc3161",
      null,
      null,
      "Basic public-test-credentials",
      "1.2.3.4",
    ),
  );
  result = decode(resumeRedirect(result.handle, "service-code", result.step.state, NOW, ENTROPY));
  result = resumeJson(result, { access_token: "bearer", token_type: "Bearer" });
  result = resumeJson(result, { credentialIDs: ["cred-1"] });
  result = resumeJson(result, {
    key: { status: "enabled", algo: ["1.2.840.113549.1.1.1"], len: 2048 },
    cert: {
      status: "valid",
      certificates: [certificate],
      subjectDN: "CN=Jane Doe,serialNumber=PNONL-123",
      serialNumber: "PNONL-123",
    },
    SCAL: "2",
  });
  result = decode(
    resumeRedirect(result.handle, "credential-code", result.step.state, NOW, ENTROPY),
  );
  result = resumeJson(result, { access_token: "SAD", token_type: "SAD" });
  return decode(resumeHttp(result.handle, 200, signHashResponse, NOW, ENTROPY)).step;
}

test("config validation accepts valid inputs and rejects a missing client ID", () => {
  assert.doesNotThrow(() =>
    validateConfig(
      "acceptance",
      "v1_rsa",
      "client-123",
      "secret",
      "https://app.example/cb",
      "https://tsa.example/rfc3161",
    ),
  );
  assert.throws(() =>
    validateConfig(
      "acceptance",
      "v1_rsa",
      "",
      "secret",
      "https://app.example/cb",
      "https://tsa.example/rfc3161",
    ),
  );
  assert.throws(() =>
    validateConfig("invalid", "v1_rsa", "client-123", "secret", "https://app.example/cb", null),
  );
  assert.throws(() =>
    validateConfig("acceptance", "invalid", "client-123", "secret", "https://app.example/cb", null),
  );
});

test("config options match the Go binding surface", () => {
  assert.doesNotThrow(() =>
    validateConfig(
      "acceptance",
      "v1_rsa",
      "client-123",
      "secret",
      "https://app.example/cb",
      "https://tsa.example/rfc3161",
      "http://localhost:9000/stub",
      "Basic public-test-credentials",
      "1.2.3.4",
    ),
  );
  assert.throws(() =>
    validateConfig(
      "acceptance",
      "v1_rsa",
      "client-123",
      "secret",
      "https://app.example/cb",
      null,
      "http://not-loopback.example/stub",
    ),
  );

  const out = beginSigning(
    PDF,
    "acceptance",
    "v1_rsa",
    "client-123",
    "secret",
    "https://app.example/cb",
    "B-T",
    NOW,
    ENTROPY,
    "https://tsa.example/rfc3161",
    null,
    "http://localhost:9000/stub",
    "Basic public-test-credentials",
    "1.2.3.4",
  );
  const resp = cbor.decodeFirstSync(out);
  assert.ok(resp.step.url.startsWith("http://localhost:9000/stub/oauth2/authorize?"));
});

test("TSA auth and policy reach the timestamp request", () => {
  const step = driveToTsaEffect();

  assert.strictEqual(step.kind, "perform_http");
  assert.strictEqual(step.url, "https://tsa.example/rfc3161");
  assert.strictEqual(
    Object.fromEntries(step.headers).Authorization,
    "Basic public-test-credentials",
  );
  assert.ok(step.body.includes(Buffer.from("06032a0304", "hex"))); // DER OBJECT IDENTIFIER 1.2.3.4
});

test("config validation rejects invalid TSA URLs", () => {
  for (const tsaUrl of [
    "not a URL",
    "ftp://tsa.example/tsr",
    "https://user:password@tsa.example/tsr",
    "https://tsa.example/tsr#response",
    "https://tsa.example:0/tsr",
  ]) {
    assert.throws(() =>
      validateConfig(
        "acceptance",
        "v1_rsa",
        "client-123",
        "secret",
        "https://app.example/cb",
        tsaUrl,
      ),
    );
  }
});

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
  assert.throws(() =>
    beginSigning(PDF, "acceptance", "NOPE", "c", "s", "https://a/cb", "B-B", NOW, ENTROPY, null),
  );
  assert.throws(() => resumeRedirect(Buffer.from("bad handle"), "c", "s", NOW, ENTROPY));
  assert.throws(() =>
    resumeRedirectError(Buffer.from("bad handle"), "access_denied", "s", NOW, ENTROPY),
  );
  assert.throws(() => resumeHttp(Buffer.from("bad handle"), 200, Buffer.alloc(0), NOW, ENTROPY));
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
