# Binding signing fixture

`binding-input.pdf` and `rsa_sign_hash_response.json` form one deterministic RSA signing vector
for the Python and Node binding contract tests. The response signs the SDK-emitted `hash[0]` for
that PDF at Unix time `1700000000` with entropy bytes `00..0f`, using
`../pki/signer-rsa.key.pk8`; `credentials/info` advertises the matching
`../pki/signer-rsa.cert.der`. The expected `hash[0]` is
`xf5/cn8hQuxGu2B559cnBxU4YcFPlA8fcBOtJn4pPZw=`. The PDF lives with the binding tests on purpose;
their contract must not depend on the separately removable reference-service example.

The vector lets both bindings reach the real B-T timestamp HTTP effect without a test-only API or
a runtime signing dependency. The tests then assert that the binding configuration reaches the
effect as the verbatim `Authorization` header and the DER-encoded request policy OID.
