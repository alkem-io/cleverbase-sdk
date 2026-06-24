# Function: resumeHttp()

> **resumeHttp**(`handle`, `status`, `body`, `nowUnix`, `entropy`): `Buffer`

Defined in: [index.d.ts:13](https://github.com/alkem-io/cleverbase-sdk/blob/84fe1cc23342a10e57274930a75b47497c2bfab1/bindings/node/index.d.ts#L13)

Resume after performing an HTTP effect (status + body). Returns a CBOR `{handle, step}` Buffer.

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
