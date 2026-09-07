# Function: beginSigning()

> **beginSigning**(`document`, `environment`, `cscApi`, `clientId`, `clientSecret`, `redirectUri`, `conformance`, `nowUnix`, `entropy`, `tsaUrl?`, `optionsJson?`, `upstreamBaseUrl?`, `tsaAuth?`, `tsaPolicyOid?`): `Buffer`

Defined in: [index.d.ts:12](https://github.com/alkem-io/cleverbase-sdk/blob/main/bindings/node/index.d.ts#L12)

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

### upstreamBaseUrl?

`string` \| `null`

### tsaAuth?

`string` \| `null`

### tsaPolicyOid?

`string` \| `null`

## Returns

`Buffer`
