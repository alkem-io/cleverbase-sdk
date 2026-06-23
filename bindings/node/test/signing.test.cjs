const test = require('node:test');
const assert = require('node:assert');
const cbor = require('cbor');
const { beginSigning, resumeRedirect } = require('../index.js');

const NOW = 1_700_000_000;
const ENTROPY = Buffer.from(Array.from({ length: 16 }, (_, i) => i));
const PDF = Buffer.from('%PDF-1.7\nminimal');

test('begin returns a service-scope redirect', () => {
  const out = beginSigning(PDF, 'acceptance', 'v1_rsa', 'client-123', 'secret', 'https://app.example/cb', 'B-B', NOW, ENTROPY, null);
  const resp = cbor.decodeFirstSync(out);
  assert.strictEqual(resp.step.kind, 'redirect');
  assert.ok(resp.step.url.includes('scope=service'));
  assert.ok(Buffer.isBuffer(resp.handle));
});

test('resume redirect emits the token exchange', () => {
  const out = beginSigning(PDF, 'acceptance', 'v1_rsa', 'client-123', 'secret', 'https://app.example/cb', 'B-B', NOW, ENTROPY, null);
  const resp = cbor.decodeFirstSync(out);
  const out2 = resumeRedirect(resp.handle, 'code-xyz', resp.step.state, NOW, ENTROPY);
  const resp2 = cbor.decodeFirstSync(out2);
  assert.strictEqual(resp2.step.kind, 'perform_http');
  assert.ok(resp2.step.url.endsWith('/oauth2/token'));
});

test('invalid document yields a failed step', () => {
  const out = beginSigning(Buffer.from('not a pdf'), 'acceptance', 'v1_rsa', 'client-123', 'secret', 'https://app.example/cb', 'B-B', NOW, ENTROPY, null);
  const resp = cbor.decodeFirstSync(out);
  assert.strictEqual(resp.step.kind, 'failed');
  assert.strictEqual(resp.step.evidence.outcome, 'invalid_document');
});
