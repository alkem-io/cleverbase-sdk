# Alkemio Cleverbase SDK for Python

The Python binding exposes the Cleverbase SDK's signing, PDF-integrity verification, and EUDI
attestation APIs through the `cleverbase` extension module. Protocol orchestration and
cryptography remain in the shared Rust core.

```bash
python -m pip install alkemio-cleverbase-sdk
```

```python
import cleverbase

verdict = cleverbase.verify_pdf(document_bytes)
if verdict["integrity"]:
    print(verdict["profile"], verdict["signer"])
else:
    print(verdict["reasons"])
```

Signing uses a resumable sans-I/O state machine: `begin_signing` and the `resume_*` functions
return CBOR envelopes describing the next HTTP or redirect effect for the host to perform. The
host supplies at least 16 fresh random bytes and a Unix timestamp whose UTC year is in
`0000..9999` on every call.

The package does not perform certificate-chain, revocation, trusted-list, signer-authorization,
or qualified-status validation. See the
[project documentation](https://github.com/alkem-io/cleverbase-sdk) for the complete API,
security model, and current limitations.
