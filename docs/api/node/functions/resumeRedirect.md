# Function: resumeRedirect()

> **resumeRedirect**(`handle`, `code`, `state`, `nowUnix`, `entropy`): `Buffer`

Defined in: [index.d.ts:14](https://github.com/alkem-io/cleverbase-sdk/blob/main/bindings/node/index.d.ts#L14)

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
