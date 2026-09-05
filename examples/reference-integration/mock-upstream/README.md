# Cleverbase reference mock

`mock-upstream` is a credential-free, deterministic stand-in for the Cleverbase
OIDC/CSC surface and an RFC 3161 TSA. It is for SDK and integration testing; it
is not a Cleverbase service and must not be used as a production upstream.

## Stable signer identities

The mock loads the committed PKI fixtures on every run. The signer certificates
and subject values are therefore stable across containers and test runs. Use
the values below when seeding a local identity mapping.

| CSC route | Key | `cleverbase_subject` expected value | Subject CN | CSC `credentials/info` `serialNumber` | Leaf certificate serial (canonical uppercase hex) |
| --- | --- | --- | --- | --- | --- |
| `/csc/v1` | RSA | `PNONL-123` | `Jane Doe` | `PNONL-123` | `07FB0DA8384404C33517B852CFE79F04C5006AC1` |
| `/csc/v2` | ECDSA P-256 | `PNONL-456` | `John Roe` | `PNONL-456` | `07FB0DA8384404C33517B852CFE79F04C5006AC2` |

`cleverbase_subject` is the `serialNumber` RDN in the certificate subject, not
the whole distinguished name. The CSC fixture deliberately returns that same
provider-style identifier in `credentials/info.serialNumber`; it is **not** the
certificate serial shown in the final column. The final column uses the SDK's
canonical certificate representation: uppercase hexadecimal, no separators and
no DER sign-padding byte.

## Local endpoints

The image listens on port `9000` and exposes `/healthz`, OIDC/CSC routes under
`/oauth2` and `/csc`, and a synthetic RFC 3161 TSA at `/tsr`. For a Compose
network whose service name is `cleverbase-refmock`, configure the signing
gateway with `TRUST_GATEWAY_TSA_URL=http://cleverbase-refmock:9000/tsr`.

The TSA and signer keys are synthetic but produce signatures that OpenSSL can
verify in the reference integration tests. They prove local wiring only; they
do not establish a qualified certificate or timestamp trust chain.
