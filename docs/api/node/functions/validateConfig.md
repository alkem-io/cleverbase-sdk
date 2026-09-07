# Function: validateConfig()

> **validateConfig**(`environment`, `cscApi`, `clientId`, `clientSecret`, `redirectUri`, `tsaUrl?`, `upstreamBaseUrl?`, `tsaAuth?`, `tsaPolicyOid?`): `void`

Defined in: [index.d.ts:10](https://github.com/alkem-io/cleverbase-sdk/blob/main/bindings/node/index.d.ts#L10)

Validate signing configuration without creating a signing session. Request-dependent rules are
checked later by `beginSigning`, which validates the configuration again.

## Parameters

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

### tsaUrl?

`string` \| `null`

### upstreamBaseUrl?

`string` \| `null`

### tsaAuth?

`string` \| `null`

### tsaPolicyOid?

`string` \| `null`

## Returns

`void`
