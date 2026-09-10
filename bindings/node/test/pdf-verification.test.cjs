const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { beginSigning, verifyPdf } = require("../index.js");

const REPO_ROOT = path.resolve(__dirname, "../../..");
const VALID_BT_PDF = path.join(REPO_ROOT, "tests/fixtures/pades-bt/rsa.pdf");
const LEGACY_BYTE_RANGE_PDF = path.join(
  REPO_ROOT,
  "tests/fixtures/pades-conformance/cleverbase-acceptance-dev-2026-09-10.pdf",
);
const YEAR_0000_START = -62_167_219_200;
const YEAR_9999_END = 253_402_300_799;

test("verifyPdf returns a typed valid verdict", () => {
  const verdict = verifyPdf(fs.readFileSync(VALID_BT_PDF));

  assert.deepStrictEqual(verdict, {
    integrity: true,
    profile: "B-T",
    signer: {
      serial: "07FB0DA8384404C33517B852CFE79F04C5006AC1",
      cn: "Jane Doe",
    },
    reasons: [],
  });
});

test("verifyPdf returns typed invalid verdicts", () => {
  for (const [document, reason] of [
    [Buffer.from("not a PDF"), "not_pdf"],
    [fs.readFileSync(LEGACY_BYTE_RANGE_PDF), "malformed_byte_range"],
  ]) {
    assert.deepStrictEqual(verifyPdf(document), {
      integrity: false,
      profile: null,
      signer: null,
      reasons: [reason],
    });
  }
});

test("beginSigning accepts the host-context year boundaries", () => {
  for (const nowUnix of [YEAR_0000_START, YEAR_9999_END]) {
    assert.ok(
      Buffer.isBuffer(
        beginSigning(
          Buffer.from("%PDF-1.7\nminimal"),
          "acceptance",
          "v1_rsa",
          "client-123",
          "secret",
          "https://app.example/cb",
          "B-B",
          nowUnix,
          Buffer.from(Array.from({ length: 16 }, (_, index) => index)),
          null,
        ),
      ),
    );
  }
});

test("beginSigning rejects an invalid host context", () => {
  for (const [nowUnix, entropy] of [
    [YEAR_0000_START - 1, Buffer.alloc(16)],
    [YEAR_9999_END + 1, Buffer.alloc(16)],
    [1_700_000_000, Buffer.alloc(15)],
  ]) {
    assert.throws(() =>
      beginSigning(
        Buffer.from("%PDF-1.7\nminimal"),
        "acceptance",
        "v1_rsa",
        "client-123",
        "secret",
        "https://app.example/cb",
        "B-B",
        nowUnix,
        entropy,
        null,
      ),
    );
  }
});
