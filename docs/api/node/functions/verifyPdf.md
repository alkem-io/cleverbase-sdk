# Function: verifyPdf()

> **verifyPdf**(`document`): [`PdfVerification`](../interfaces/PdfVerification.md)

Defined in: [index.d.ts:63](https://github.com/alkem-io/cleverbase-sdk/blob/main/bindings/node/index.d.ts#L63)

Verify one PDF's ByteRange and embedded CMS signature.

Invalid input returns a typed verdict with integrity false; this operation does not establish
certificate-chain trust, revocation status, signer authorization, TSA trust, or TSA policy.

## Parameters

### document

`Buffer`

## Returns

[`PdfVerification`](../interfaces/PdfVerification.md)
