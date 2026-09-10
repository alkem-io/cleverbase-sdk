# Function: resumeRedirect()

> **resumeRedirect**(`handle`, `code`, `state`, `nowUnix`, `entropy`): `Buffer`

Defined in: [index.d.ts:42](https://github.com/alkem-io/cleverbase-sdk/blob/main/bindings/node/index.d.ts#L42)

Resume after an OAuth code and state redirect. Returns a CBOR handle/step Buffer.

nowUnix and entropy follow beginSigning's host-context contract; entropy must be fresh for this
call.

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
