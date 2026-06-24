# Function: resumeRedirect()

> **resumeRedirect**(`handle`, `code`, `state`, `nowUnix`, `entropy`): `Buffer`

Defined in: [index.d.ts:9](https://github.com/alkem-io/cleverbase-sdk/blob/main/bindings/node/index.d.ts#L9)

Resume after a redirect return (OAuth `code` + `state`). Returns a CBOR `{handle, step}` Buffer.

## Parameters

### handle

`Buffer`

### code

`string`

### state

`string`

### nowUnix

`number`

### entropy

`Buffer`

## Returns

`Buffer`
