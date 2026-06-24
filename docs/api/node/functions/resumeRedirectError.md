# Function: resumeRedirectError()

> **resumeRedirectError**(`handle`, `error`, `state`, `nowUnix`, `entropy`): `Buffer`

Defined in: [index.d.ts:11](https://github.com/alkem-io/cleverbase-sdk/blob/84fe1cc23342a10e57274930a75b47497c2bfab1/bindings/node/index.d.ts#L11)

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
