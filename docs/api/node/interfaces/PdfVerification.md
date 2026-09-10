# Interface: PdfVerification

Defined in: [index.d.ts:14](https://github.com/alkem-io/cleverbase-sdk/blob/main/bindings/node/index.d.ts#L14)

Integrity-only verdict for one PDF signature.

## Properties

### integrity

> **integrity**: `boolean`

Defined in: [index.d.ts:16](https://github.com/alkem-io/cleverbase-sdk/blob/main/bindings/node/index.d.ts#L16)

Whether the CMS signature and signed PDF bytes are internally consistent.

***

### profile

> **profile**: `string` \| `null`

Defined in: [index.d.ts:18](https://github.com/alkem-io/cleverbase-sdk/blob/main/bindings/node/index.d.ts#L18)

PAdES profile, or null when integrity is false.

***

### reasons

> **reasons**: `string`[]

Defined in: [index.d.ts:22](https://github.com/alkem-io/cleverbase-sdk/blob/main/bindings/node/index.d.ts#L22)

Machine-readable snake_case failure codes; empty when integrity is true.

***

### signer

> **signer**: [`PdfSigner`](PdfSigner.md) \| `null`

Defined in: [index.d.ts:20](https://github.com/alkem-io/cleverbase-sdk/blob/main/bindings/node/index.d.ts#L20)

Embedded signer identity, or null when integrity is false.
