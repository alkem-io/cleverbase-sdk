# Cleverbase hash-signing stub certificate fixture

`cleverbase-hash-signing-stub-leaf.b64` is the public leaf certificate returned by the Cleverbase
hash-signing service stub's `POST /csc/v1/credentials/info` response. It exercises the CSC case
where `cert.subjectDN` and `cert.serialNumber` are absent and identity must be derived from the
leaf certificate.

- Source: [Cleverbase hash-signing service stub](https://trust-driver-stub-hash-signing.cleverbase.com/docs/),
  `POST /csc/v1/credentials/info`
- Retrieved: 2026-09-05
- SHA-256 fingerprint: `49:6F:C4:E6:9A:E7:70:EB:72:BE:90:3B:BE:04:B9:23:C3:CF:86:67:99:7A:01:AC:7A:59:76:CF:6B:5D:5A:15`
- Subject: `CN=WILLEKE LISELOTTE DE BRUIJN, GN=WILLEKE LISELOTTE, SN=DE BRUIJN,
  serialNumber=HB-5c699eab-1c61-41c5-9318-246a936c4ec6, C=NL`
- Issuer: `TEST Cleverbase ID PKIoverheid Burger CA - G3`
- Validity: 2026-01-29 15:41:29 UTC through 2028-01-29 16:08:32 UTC

The fixture is public test material, not an acceptance or production signer certificate. Do not
reuse it as a trust anchor.
