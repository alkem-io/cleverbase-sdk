// Demo: start a signing flow with the Cleverbase Node binding.
//
// Build first:  (cd bindings/node && npm install && npm run build)
// Run:          node examples/node_demo.mjs
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import cbor from "cbor";

const require = createRequire(import.meta.url);
const cleverbase = require("../bindings/node/index.js");

const pdf = Buffer.from("%PDF-1.7\n... your document ...");
const out = cleverbase.beginSigning(
  pdf,
  "acceptance",
  "v1_rsa",
  "your-client-id",
  "your-client-secret",
  "https://your-app.example/callback",
  "B-B",
  Math.floor(Date.now() / 1000), // the core is sans-IO; host supplies the clock
  randomBytes(16),
  null,
);
const resp = cbor.decodeFirstSync(out);
console.log(`First step: ${resp.step.kind}`);
if (resp.step.kind === "redirect") {
  console.log(`Send the signer to:\n  ${resp.step.url}`);
  console.log("Persist resp.handle server-side; resume with the returned code+state.");
}
