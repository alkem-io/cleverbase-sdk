# Function: beginSigning()

> **beginSigning**(`document`, `environment`, `cscApi`, `clientId`, `clientSecret`, `redirectUri`, `conformance`, `nowUnix`, `entropy`, `tsaUrl?`, `optionsJson?`): `Buffer`

Defined in: [index.d.ts:7](https://github.com/alkem-io/cleverbase-sdk/blob/main/bindings/node/index.d.ts#L7)

Begin a signing flow. Returns a CBOR `{handle, step}` Buffer (decode-only for the caller).

## Parameters

### document

`Buffer`

### environment

`string`

### cscApi

`string`

### clientId

`string`

### clientSecret

`string`

### redirectUri

`string`

### conformance

`string`

### nowUnix

`number`

### entropy

`Buffer`

### tsaUrl?

`string` \| `null`

### optionsJson?

`string` \| `null`

## Returns

`Buffer`
