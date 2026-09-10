# Function: resumeHttp()

> **resumeHttp**(`handle`, `status`, `body`, `nowUnix`, `entropy`): `Buffer`

Defined in: [index.d.ts:56](https://github.com/alkem-io/cleverbase-sdk/blob/main/bindings/node/index.d.ts#L56)

Resume after performing an HTTP effect (status + body). Returns a CBOR handle/step Buffer.

nowUnix and entropy follow beginSigning's host-context contract; entropy must be fresh for this
call.

## Parameters

### handle

`Buffer`

### status

`number`

### body

`Buffer`

### nowUnix

`number`

### entropy

`Buffer`

## Returns

`Buffer`
