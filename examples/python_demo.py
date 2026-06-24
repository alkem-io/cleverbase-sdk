#!/usr/bin/env python3
"""Demo: start a signing flow with the Cleverbase Python binding.

Build the binding first:
    python3 -m venv .venv && .venv/bin/pip install maturin cbor2
    (cd bindings/python && PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 ../../.venv/bin/maturin develop)
Then run:
    .venv/bin/python examples/python_demo.py
"""

import os
import time

import cbor2
import cleverbase

# A real integrator passes the PDF bytes + their Cleverbase client config.
pdf = b"%PDF-1.7\n... your document ..."
out = cleverbase.begin_signing(
    pdf,
    "acceptance",  # environment
    "v1_rsa",  # CSC API generation
    "your-client-id",
    "your-client-secret",
    "https://your-app.example/callback",
    "B-B",  # PAdES conformance level
    int(time.time()),  # now (the core is sans-IO; host supplies the clock)
    os.urandom(16),  # entropy for OAuth state
)
resp = cbor2.loads(out)
step = resp["step"]
print(f"SDK schema version: {cleverbase.SCHEMA_VERSION}")
print(f"First step: {step['kind']}")
if step["kind"] == "redirect":
    print(f"Send the signer to:\n  {step['url']}")
    print("Persist resp['handle'] server-side; resume with the returned code+state.")
