# Function: resumeRedirectError()

> **resumeRedirectError**(`handle`, `error`, `state`, `nowUnix`, `entropy`): `Buffer`

Defined in: [index.d.ts:49](https://github.com/alkem-io/cleverbase-sdk/blob/main/bindings/node/index.d.ts#L49)

Resume after an OAuth error redirect. Returns a CBOR handle/step Buffer.

nowUnix and entropy follow beginSigning's host-context contract; entropy must be fresh for this
call.

## Parameters

### handle

`Buffer`

### error

`string`

### state

`string`

### nowUnix

`number`

### entropy

`Buffer`

## Returns

`Buffer`
