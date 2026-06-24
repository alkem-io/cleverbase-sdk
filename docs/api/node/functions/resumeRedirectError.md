# Function: resumeRedirectError()

> **resumeRedirectError**(`handle`, `error`, `state`, `nowUnix`, `entropy`): `Buffer`

Defined in: [index.d.ts:11](https://github.com/alkem-io/cleverbase-sdk/blob/main/bindings/node/index.d.ts#L11)

Resume after a redirect OAuth error (`error` + `state`). Returns a CBOR `{handle, step}` Buffer.

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
